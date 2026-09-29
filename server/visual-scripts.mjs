// Runs in the inspected main frame. Returns metadata, never asset bytes or SVG markup.
export function extractVisuals({ captureId }) {
  const observer = window.__wiObserver;
  const limits = {
    scannedElements: 4000,
    owners: 300,
    usages: 1200,
    cssRules: 2000,
    performanceEntries: 1000,
    sourceCharacters: 8192,
    cssValueCharacters: 64000,
  };
  const owners = [],
    usages = [],
    sheets = [],
    gaps = [];
  const nodes = [...document.querySelectorAll('*')];
  let rulesVisited = 0;
  const rules = [],
    faces = [];
  let oversized = 0;
  const omitted = (kind) => `wi-truncated:${kind}:${captureId}:${++oversized}`;
  const bounded = (value) =>
    value && String(value).length > limits.sourceCharacters
      ? omitted(
          String(value).startsWith('data:')
            ? 'data'
            : String(value).startsWith('blob:')
              ? 'blob'
              : 'unknown',
        )
      : value;
  const urls = (value) => {
    const raw = String(value || '');
    if (raw.length > limits.cssValueCharacters) return [omitted('unknown')];
    const result = [];
    for (const m of raw.matchAll(/url\(\s*(?:"([^"]*)"|'([^']*)'|([^)]*))\s*\)/gi)) {
      result.push(bounded((m[1] ?? m[2] ?? m[3]).trim()));
      if (result.length >= 12) break;
    }
    return result;
  };
  const resolve = (value, base = document.baseURI) => {
    try {
      return bounded(new URL(bounded(value), base).href);
    } catch {
      return null;
    }
  };
  const text = (value) => String(value || '').slice(0, 300);
  const readRules = (sheet, source, depth = 0, prefix = '') => {
    source = bounded(source);
    if (depth > 8 || rulesVisited >= limits.cssRules) return;
    let list;
    try {
      list = sheet.cssRules;
    } catch {
      sheets.push({
        source,
        accessible: false,
        reason: 'CSSOM access denied (for example cross-origin stylesheet)',
      });
      return;
    }
    if (!depth) sheets.push({ source, accessible: true });
    for (let i = 0; i < list.length && rulesVisited < limits.cssRules; i++) {
      const rule = list[i],
        rulePath = `${prefix}${i}`;
      rulesVisited++;
      if (rule.selectorText && rule.style) rules.push({ rule, source, rulePath });
      if (rule.type === CSSRule.FONT_FACE_RULE)
        faces.push({
          family: rule.style.fontFamily.replace(/["']/g, ''),
          sources: urls(rule.style.src).map((x) => resolve(x, source || document.baseURI)),
          source,
          rulePath,
        });
      if (rule.styleSheet)
        readRules(rule.styleSheet, rule.href || source, depth + 1, `${rulePath}.`);
      else if (rule.cssRules) readRules(rule, source, depth + 1, `${rulePath}.`);
    }
  };
  for (const sheet of [...document.styleSheets].slice(0, 80)) readRules(sheet, sheet.href || null);
  const owner = (el) => {
    const nodeId = observer.identity(el),
      id = `${captureId}:el:${nodeId}`;
    if (!owners.some((x) => x.id === id)) {
      if (owners.length >= limits.owners) return null;
      const rect = el.getBoundingClientRect();
      owners.push({
        id,
        domNodeId: nodeId,
        selector: observer.selector(el),
        tag: el.tagName.toLowerCase(),
        type: 'visual',
        label: text(
          el.getAttribute('aria-label') ||
            el.getAttribute('alt') ||
            el.id ||
            el.tagName.toLowerCase(),
        ),
        bounds: {
          x: Math.max(0, rect.left + scrollX),
          y: Math.max(0, rect.top + scrollY),
          width: rect.width,
          height: rect.height,
        },
        listeners: [],
        delegated: [],
        name: null,
        form: null,
        href: null,
      });
    }
    return id;
  };
  const add = (el, type, role, url, details = {}) => {
    if (usages.length >= limits.usages) return;
    const elementId = owner(el);
    if (elementId) usages.push({ elementId, type, role, url: bounded(url), ...details });
  };
  // HTML's URL token can contain commas (notably data URLs); descriptors end at a comma.
  const srcset = (value) => {
    const result = [];
    let rest = String(value || '').trim();
    while (rest && result.length < 40) {
      rest = rest.replace(/^[\s,]+/, '');
      const match = rest.match(/^\S+/);
      if (!match) break;
      let url = match[0];
      rest = rest.slice(url.length);
      if (url.endsWith(',')) {
        url = url.replace(/,+$/, '');
        result.push({ url, descriptor: '' });
        continue;
      }
      const end = rest.indexOf(',');
      result.push({ url, descriptor: (end < 0 ? rest : rest.slice(0, end)).trim().slice(0, 80) });
      rest = end < 0 ? '' : rest.slice(end + 1);
    }
    return result;
  };
  for (const el of nodes.slice(0, limits.scannedElements)) {
    if (usages.length >= limits.usages || owners.length >= limits.owners) break;
    if (el instanceof HTMLImageElement) {
      const state = {
        loading: el.loading || 'eager',
        complete: el.complete,
        naturalWidth: el.naturalWidth,
        naturalHeight: el.naturalHeight,
        renderedWidth: el.getBoundingClientRect().width,
        renderedHeight: el.getBoundingClientRect().height,
        inViewport:
          el.getBoundingClientRect().top < innerHeight && el.getBoundingClientRect().bottom > 0,
        sizes: text(el.sizes),
      };
      if (el.getAttribute('src'))
        add(el, 'image', 'declared', resolve(el.getAttribute('src')), {
          declaration: 'img.src',
          state,
        });
      for (const item of srcset(el.srcset))
        add(el, 'image', 'declared', resolve(item.url), {
          declaration: 'img.srcset',
          descriptor: item.descriptor,
          state,
        });
      for (const source of el.parentElement?.tagName === 'PICTURE'
        ? el.parentElement.querySelectorAll('source')
        : [])
        for (const item of srcset(source.srcset))
          add(el, 'image', 'declared', resolve(item.url), {
            declaration: 'picture/source.srcset',
            media: text(source.media),
            descriptor: item.descriptor,
            state,
          });
      if (el.currentSrc)
        add(el, 'image', 'selected', resolve(el.currentSrc), {
          declaration: 'img.currentSrc',
          state,
        });
    }
    if (el.tagName.toLowerCase() === 'svg')
      add(el, 'svg', 'inline', null, {
        declaration: 'inline SVG DOM',
        viewBox: text(el.getAttribute('viewBox')),
        inlineId: observer.identity(el),
      });
    if (el.tagName.toLowerCase() === 'use') {
      const href = el.getAttribute('href') || el.getAttribute('xlink:href');
      if (href)
        add(el, 'svg', 'declared', href.startsWith('#') ? null : resolve(href), {
          declaration: 'svg/use href',
          localTarget: href.startsWith('#') ? text(href) : null,
          targetNodeId:
            href.startsWith('#') && document.getElementById(href.slice(1))
              ? observer.identity(document.getElementById(href.slice(1)))
              : null,
          inlineId: href.startsWith('#') ? text(href) : null,
        });
    }
    if (el instanceof HTMLScriptElement && el.src)
      add(el, 'script', 'declared', el.src, { declaration: 'script.src' });
    if (el instanceof HTMLLinkElement && /stylesheet|icon/i.test(el.rel))
      add(el, /icon/i.test(el.rel) ? 'favicon' : 'stylesheet', 'declared', el.href, {
        declaration: `link[rel=${text(el.rel)}]`,
      });
    // Full CSS is not serialized: only asset-related property metadata is retained.
    for (const pseudo of [null, '::before', '::after']) {
      const style = getComputedStyle(el, pseudo);
      const selected = [
        ...urls(style.backgroundImage).map((url) => ({ url, property: 'background-image' })),
        ...urls(style.content).map((url) => ({ url, property: 'content' })),
      ];
      for (const entry of selected) {
        const matches = [];
        for (const { rule, source, rulePath } of rules) {
          if (matches.length >= 8) break;
          const selectors = rule.selectorText
            .split(',')
            .filter((s) => (pseudo ? s.trim().endsWith(pseudo) : !s.includes('::')));
          let matchesElement = false;
          for (const candidate of selectors) {
            try {
              if (el.matches(pseudo ? candidate.trim().slice(0, -pseudo.length) : candidate))
                matchesElement = true;
            } catch {}
          }
          if (!matchesElement) continue;
          for (const declared of urls(rule.style.getPropertyValue(entry.property)))
            matches.push({
              source,
              rulePath,
              selector: text(rule.selectorText),
              property: entry.property,
              url: resolve(declared, source || document.baseURI),
            });
        }
        add(el, 'background', 'computed', resolve(entry.url), {
          declaration: `computed ${pseudo || 'element'} ${entry.property}`,
          pseudo,
          position: style.backgroundPosition,
          size: style.backgroundSize,
          repeat: style.backgroundRepeat,
          inlineDeclaration:
            !pseudo && el.style.getPropertyValue(entry.property)
              ? {
                  property: entry.property,
                  source: 'HTML style attribute',
                  assets: urls(el.style.getPropertyValue(entry.property)).map((u) => resolve(u)),
                }
              : null,
          rules: matches,
          ruleSourceStatus: matches.length
            ? 'matching declarations; cascade winner not proven'
            : 'unknown: inline/inherited/inaccessible rule or no matching rule',
          sprite:
            style.backgroundPosition !== '0% 0%'
              ? 'inferred candidate from background position; sprite semantics unknown'
              : 'unknown',
        });
        for (const match of matches)
          add(el, 'background', 'declared', match.url, {
            declaration: `CSS rule ${match.property}`,
            pseudo,
            ruleSource: match.source,
            rulePath: match.rulePath,
            selector: match.selector,
            cascade: 'candidate declaration; active media/cascade winner not established',
          });
      }
      const glyph = pseudo ? style.content : el.childElementCount === 0 ? el.textContent : '';
      if (
        glyph &&
        (/[\uE000-\uF8FF]/.test(glyph) ||
          (!pseudo && /\bicon\b/i.test(el.className?.baseVal || el.className)))
      ) {
        const candidates = faces.filter((face) =>
          style.fontFamily
            .split(',')
            .map((s) => s.trim().replace(/["']/g, ''))
            .includes(face.family),
        );
        add(el, 'font', 'inferred', null, {
          declaration: 'possible icon glyph',
          pseudo,
          inlineId: `font:${style.fontFamily}`,
          family: style.fontFamily,
          fontSetStatus: document.fonts.status,
          fontFaces: candidates,
          actualPaintedFont: 'unknown: fallback and actual glyph face not traced',
        });
        for (const face of candidates)
          for (const url of face.sources)
            add(el, 'font', 'declared', url, {
              declaration: '@font-face candidate',
              pseudo,
              family: face.family,
              ruleSource: face.source,
              rulePath: face.rulePath,
            });
      }
    }
  }
  const entries = performance.getEntriesByType('resource');
  const performanceEntries = entries.slice(-limits.performanceEntries).map((e) => ({
    url: bounded(e.name),
    initiatorType: e.initiatorType,
    startTime: e.startTime,
    duration: e.duration,
    transferSize: e.transferSize,
    decodedBodySize: e.decodedBodySize,
    cache: 'unknown: zero transfer can also mean cross-origin timing restriction',
  }));
  if (nodes.length > limits.scannedElements) gaps.push('DOM scan truncated at 4000 elements');
  if (owners.length >= limits.owners) gaps.push('Visual owner limit 300 reached');
  if (usages.length >= limits.usages) gaps.push('Visual usage limit 1200 reached');
  if (rulesVisited >= limits.cssRules) gaps.push('CSS rule limit 2000 reached');
  if (document.styleSheets.length > 80) gaps.push('Stylesheet scan truncated at 80');
  if (entries.length > limits.performanceEntries)
    gaps.push('Only last 1000 resource timing entries retained');
  if (oversized)
    gaps.push(
      `${oversized} source/CSS values omitted at size limits; exact identity/network matching unavailable for them`,
    );
  return {
    documentId: observer.documentId,
    owners,
    usages,
    sheets,
    performanceEntries,
    performanceTimeOrigin: performance.timeOrigin,
    limits,
    gaps,
    coverage: {
      frame: 'main frame only',
      iframeCount: document.querySelectorAll('iframe').length,
      openShadowHosts: nodes.slice(0, limits.scannedElements).filter((el) => el.shadowRoot).length,
      shadowDOM: 'not traversed; closed roots cannot be enumerated',
      serviceWorker: 'blocked by collector context; requests may differ from daily browser',
      cache: 'no universal cache provenance; interception disables normal HTTP cache',
      requests:
        'only collection window; earlier/evicted timing entries and failed instrumentation may be missing',
      source:
        'DOM/CSS metadata only; backend, framework state, controller, database and storage origin unknown',
      screenshot: 'sequential acquisition; dynamic DOM may move between extraction and screenshot',
    },
  };
}
