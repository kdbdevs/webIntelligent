// This code runs in the audited page. Never collect input values or function source.
export function installObserver() {
  const original = EventTarget.prototype.addEventListener;
  const registry = new WeakMap();
  const uid = () =>
    [...crypto.getRandomValues(new Uint8Array(16))]
      .map((x) => x.toString(16).padStart(2, '0'))
      .join('');
  const identities = new WeakMap();
  let sequence = 0;
  const identity = (el) => {
    if (!identities.has(el)) identities.set(el, `n${++sequence}`);
    return identities.get(el);
  };
  const state = { registry, lastEvent: null, documentId: uid(), identity };
  Object.defineProperty(window, '__wiObserver', { value: state, configurable: true });
  const selector = (el) => {
    if (!(el instanceof Element)) return el === document ? 'document' : 'window';
    if (el.id) return `#${CSS.escape(el.id)}`;
    const parts = [];
    for (let n = el; n && n !== document.documentElement && parts.length < 6; n = n.parentElement) {
      const siblings = n.parentElement
        ? [...n.parentElement.children].filter((x) => x.tagName === n.tagName)
        : [];
      parts.unshift(
        n.tagName.toLowerCase() +
          (siblings.length > 1 ? `:nth-of-type(${siblings.indexOf(n) + 1})` : ''),
      );
    }
    return parts.join(' > ');
  };
  state.selector = selector;
  const emit = (data) => {
    try {
      window.__wiReport?.({ ...data, documentId: state.documentId }).catch(() => {});
    } catch {}
  };
  EventTarget.prototype.addEventListener = function (type, handler, options) {
    if (['click', 'input', 'change', 'submit', 'keydown'].includes(type)) {
      const items = registry.get(this) || [];
      if (items.length < 30)
        items.push({
          event: type,
          handler: typeof handler === 'function' ? handler.name || '(anonymous)' : 'handleEvent',
          registration: new Error().stack?.split('\n').slice(2, 5).join('\n') || '',
        });
      registry.set(this, items);
    }
    return original.call(this, type, handler, options);
  };
  for (const type of ['click', 'input', 'change', 'submit'])
    original.call(
      document,
      type,
      (event) => {
        const el = event.target;
        if (!(el instanceof Element)) return;
        const data = {
          kind: 'event',
          id: uid(),
          domNodeId: identity(el),
          formNodeId: el.form ? identity(el.form) : null,
          event: type,
          selector: selector(el),
          name: el.getAttribute('name') || '',
          tag: el.tagName.toLowerCase(),
          formSelector: el.form ? selector(el.form) : el.tagName === 'FORM' ? selector(el) : null,
          time: Date.now(),
        };
        state.lastEvent = data;
        emit(data);
      },
      true,
    );
  const reportCall = (url, method, transport) =>
    emit({
      kind: 'initiator',
      url: String(url),
      method,
      transport,
      stack: new Error().stack,
      eventId:
        state.lastEvent && Date.now() - state.lastEvent.time < 1500 ? state.lastEvent.id : null,
    });
  const realFetch = window.fetch;
  window.fetch = function (input, init) {
    reportCall(
      input instanceof Request ? input.url : input,
      String(init?.method || (input instanceof Request ? input.method : 'GET')).toUpperCase(),
      'fetch',
    );
    return Reflect.apply(realFetch, this, arguments);
  };
  const open = XMLHttpRequest.prototype.open;
  const send = XMLHttpRequest.prototype.send;
  const xhrMeta = new WeakMap();
  XMLHttpRequest.prototype.open = function (method, url) {
    xhrMeta.set(this, { method: String(method).toUpperCase(), url });
    return Reflect.apply(open, this, arguments);
  };
  XMLHttpRequest.prototype.send = function () {
    const m = xhrMeta.get(this);
    if (m) reportCall(m.url, m.method, 'XMLHttpRequest');
    return Reflect.apply(send, this, arguments);
  };
  // Structural metadata only: never serialize changed text, attributes, or form values.
  let mutationCount = 0,
    pending = [],
    timer;
  new MutationObserver((records) => {
    mutationCount += records.length;
    for (const record of records.slice(0, 20)) {
      if (pending.length >= 20) break;
      const el = record.target instanceof Element ? record.target : record.target.parentElement;
      if (el)
        pending.push({
          domNodeId: identity(el),
          selector: selector(el),
          type: record.type,
          attribute: record.attributeName,
          added: record.addedNodes.length,
          removed: record.removedNodes.length,
        });
    }
    if (!timer)
      timer = setTimeout(() => {
        emit({
          kind: 'change',
          type: 'DOM mutation batch',
          changes: pending,
          count: mutationCount,
          time: Date.now(),
        });
        pending = [];
        mutationCount = 0;
        timer = null;
      }, 250);
  }).observe(document, { subtree: true, childList: true, attributes: true, characterData: true });
  for (const method of ['pushState', 'replaceState']) {
    const real = history[method];
    history[method] = function () {
      const result = Reflect.apply(real, this, arguments);
      emit({ kind: 'change', type: method, url: location.href, time: Date.now() });
      return result;
    };
  }
  for (const type of ['popstate', 'hashchange'])
    original.call(window, type, () =>
      emit({ kind: 'change', type, url: location.href, time: Date.now() }),
    );
}

export function extractPage({ captureId } = {}) {
  const observer = window.__wiObserver;
  const selector =
    observer?.selector || ((el) => (el.id ? `#${CSS.escape(el.id)}` : el.tagName.toLowerCase()));
  const text = (value, max = 160) =>
    String(value || '')
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, max);
  const visible = (el) => {
    const r = el.getBoundingClientRect(),
      s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
  };
  const forms = [...document.forms].slice(0, 80).map((form) => ({
    selector: selector(form),
    action: form.action,
    method: form.method.toUpperCase(),
    enctype: form.enctype,
    declaredAction: form.getAttribute('action'),
    declaredMethod: form.getAttribute('method'),
    fields: [...form.elements]
      .filter((el) => el.name && !el.disabled)
      .slice(0, 100)
      .map((el) => ({
        name: el.name,
        type: el.type || el.tagName.toLowerCase(),
        required: !!el.required,
      })),
  }));
  const candidates = [
    ...document.querySelectorAll(
      'form,a[href],input:not([type="hidden"]),textarea,select,button,[role="button"],[role="link"],[contenteditable="true"]',
    ),
  ].filter(visible);
  const elements = candidates.slice(0, 250).map((el, index) => {
    const rect = el.getBoundingClientRect();
    const type = el.type || el.getAttribute('role') || el.tagName.toLowerCase();
    const isField = ['INPUT', 'SELECT', 'TEXTAREA'].includes(el.tagName);
    const label = text(
      el.getAttribute('aria-label') ||
        el.labels?.[0]?.textContent ||
        (el.tagName === 'FORM'
          ? `Form ${el.name || el.id || selector(el)}`
          : isField
            ? el.name || el.getAttribute('placeholder')
            : el.textContent) ||
        el.getAttribute('title') ||
        type,
    );
    const listeners = [...(observer?.registry.get(el) || [])].map((item) => ({
      ...item,
      scope: 'direct',
    }));
    for (const event of ['click', 'input', 'change', 'submit']) {
      if (typeof el[`on${event}`] === 'function')
        listeners.push({
          event,
          handler: el[`on${event}`].name || '(property handler)',
          scope: 'direct',
          registration: '',
        });
    }
    const ancestors = [];
    for (let n = el.parentElement; n && ancestors.length < 8; n = n.parentElement)
      ancestors.push(n);
    ancestors.push(document, window);
    const delegated = ancestors
      .flatMap((node) =>
        (observer?.registry.get(node) || []).map((item) => ({
          ...item,
          scope: 'ancestor / potentially delegated',
          owner: selector(node),
        })),
      )
      .slice(0, 16);
    const form =
      el.tagName === 'FORM'
        ? forms.find((f) => f.selector === selector(el))
        : el.form
          ? forms.find((f) => f.selector === selector(el.form))
          : null;
    return {
      id: captureId ? `${captureId}:el:${observer.identity(el)}` : `e${index + 1}`,
      ordinal: index + 1,
      domNodeId: observer?.identity(el) || null,
      selector: selector(el),
      tag: el.tagName.toLowerCase(),
      type,
      label,
      name: el.name || null,
      required: !!el.required,
      disabled: !!el.disabled,
      href: el instanceof HTMLAnchorElement ? el.href : null,
      form: form
        ? {
            ...form,
            action: el.hasAttribute('formaction') ? el.formAction : form.action,
            method: el.hasAttribute('formmethod') ? el.formMethod.toUpperCase() : form.method,
          }
        : null,
      listeners: listeners.slice(0, 15),
      delegated,
      bounds: {
        x: Math.max(0, rect.left + scrollX),
        y: Math.max(0, rect.top + scrollY),
        width: rect.width,
        height: rect.height,
      },
    };
  });
  return {
    documentId: observer?.documentId || null,
    title: document.title,
    url: location.href,
    elements,
    forms,
    links: [...document.querySelectorAll('a[href]')]
      .slice(0, 500)
      .map((a) => ({ label: text(a.textContent || a.getAttribute('aria-label')), href: a.href })),
    documentHeight: Math.max(document.documentElement.scrollHeight, innerHeight),
    viewport: { width: innerWidth, height: innerHeight },
    totalElements: candidates.length,
    truncated: candidates.length > 250,
    iframeCount: document.querySelectorAll('iframe').length,
    technologies: [
      {
        name: document.querySelector('#__next,script#__NEXT_DATA__')
          ? 'Next.js marker'
          : document.querySelector('[data-reactroot]')
            ? 'React marker'
            : 'DOM / JavaScript',
        evidence: 'DOM marker only',
      },
    ],
  };
}
