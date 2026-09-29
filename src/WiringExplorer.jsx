import React, { useEffect, useMemo, useState } from 'react';
import { ReactFlow, Background, Controls, MarkerType } from '@xyflow/react';

const colors = {
  observed: '#21836d',
  declared: '#5277bf',
  correlated: '#ae791d',
  inferred: '#a263ad',
  unknown: '#77818d',
};
const artifactUrl = (job, id) => `/api/cases/${job.caseId}/runs/${job.id}/artifacts/${id}/content`;
function ScreenshotCrop({ job, page, element }) {
  const b = element?.bounds;
  if (
    !page.screenshotArtifactId ||
    !b ||
    b.width <= 0 ||
    b.height <= 0 ||
    b.y >= page.screenshotHeight
  )
    return null;
  const scale = Math.min(3, 220 / b.width),
    height = Math.min(200, b.height * scale, (page.screenshotHeight - b.y) * scale);
  return (
    <div
      className="wiring-crop"
      style={{ width: Math.min(220, b.width * scale), height }}
      aria-label={`Potongan screenshot ${element.selector}`}
    >
      <img
        alt="Potongan PNG terverifikasi"
        src={artifactUrl(job, page.screenshotArtifactId)}
        style={{ width: page.screenshotWidth * scale, left: -b.x * scale, top: -b.y * scale }}
      />
    </div>
  );
}

export function WiringExplorer({
  job,
  page,
  element,
  onElementSelect,
  onPageSelect,
  initialFocus,
}) {
  const [graph, setGraph] = useState(null),
    [error, setError] = useState('');
  const [focus, setFocus] = useState(null),
    [detail, setDetail] = useState(null),
    [assetId, setAssetId] = useState(null);
  const [search, setSearch] = useState(''),
    [type, setType] = useState(''),
    [domain, setDomain] = useState(''),
    [count, setCount] = useState(40);
  const [onlyElement, setOnlyElement] = useState(false);
  useEffect(() => {
    let active = true;
    setGraph(null);
    setError('');
    setAssetId(null);
    setDetail(null);
    setCount(40);
    setSearch('');
    setType('');
    setDomain('');
    if (page.wiring)
      fetch(artifactUrl(job, page.wiring.artifactId))
        .then(async (r) => {
          const data = await r.json();
          if (!r.ok) throw new Error(data.error || 'Verifikasi artefak gagal');
          if (active) setGraph(data);
        })
        .catch((e) => active && setError(e.message));
    return () => {
      active = false;
    };
  }, [job.caseId, job.id, page.wiring?.artifactId]);
  useEffect(() => {
    setFocus(element?.id || initialFocus);
    setAssetId(null);
    setDetail(null);
  }, [element?.id, page.captureId, initialFocus]);
  const asset = graph?.assets.find((a) => a.id === assetId);
  const visibleAssets = useMemo(
    () =>
      (graph?.assets || []).filter(
        (a) =>
          (!onlyElement || a.uses.some((u) => u.elementId === element?.id)) &&
          (!type || a.type === type) &&
          (!domain || (a.source.domain || '(inline / data)') === domain) &&
          `${a.source.url || ''} ${a.type} ${a.uses.map((u) => u.declaration).join(' ')} ${a.uses.map((u) => page.elements.find((e) => e.id === u.elementId)?.selector || '').join(' ')}`
            .toLowerCase()
            .includes(search.toLowerCase()),
      ),
    [graph, type, domain, search, page, element?.id, onlyElement],
  );
  const flow = useMemo(() => {
    if (!graph) return { nodes: [], edges: [], total: 0 };
    const selected = focus || graph.nodes[0]?.id,
      ids = new Set([selected]);
    let frontier = [selected];
    for (let depth = 0; depth < 3; depth++) {
      const next = [];
      for (const e of graph.edges) {
        if (ids.size >= 80) break;
        // An unknown-backend node is a boundary, not a shortcut joining every request.
        const traversable = frontier.filter(
          (id) => id === selected || graph.nodes.find((n) => n.id === id)?.type !== 'unknown',
        );
        if (!traversable.includes(e.source) && !traversable.includes(e.target)) continue;
        for (const id of [e.source, e.target])
          if (!ids.has(id)) {
            ids.add(id);
            next.push(id);
          }
      }
      frontier = next;
    }
    const columns = {
        element: 0,
        event: 1,
        handler: 1,
        navigation: 1,
        declaration: 1,
        parameter: 2,
        change: 2,
        asset: 2,
        request: 3,
        domain: 3,
        response: 4,
        unknown: 4,
      },
      rows = {};
    const nodes = graph.nodes
      .filter((n) => ids.has(n.id))
      .map((n) => {
        const col = columns[n.type] || 0,
          row = rows[col] || 0;
        rows[col] = row + 1;
        return {
          id: n.id,
          position: { x: col * 270, y: row * 115 },
          data: {
            label: (
              <>
                <strong>
                  {n.type} · {n.relation}
                </strong>
                <span>{n.label.slice(0, 100)}</span>
              </>
            ),
          },
          style: {
            width: 235,
            borderColor: colors[n.relation],
            borderWidth: n.id === selected ? 3 : 1,
            background: n.id === selected ? '#edf8f4' : '#fff',
          },
          sourcePosition: 'right',
          targetPosition: 'left',
        };
      });
    return {
      nodes,
      total: ids.size,
      edges: graph.edges
        .filter((e) => ids.has(e.source) && ids.has(e.target))
        .slice(0, 180)
        .map((e) => ({
          ...e,
          label: e.relation,
          style: {
            stroke: colors[e.relation],
            strokeDasharray: ['unknown', 'correlated', 'inferred'].includes(e.relation)
              ? '5 4'
              : undefined,
          },
          markerEnd: { type: MarkerType.ArrowClosed, color: colors[e.relation] },
        })),
    };
  }, [graph, focus]);
  const selectedElements = asset
    ? page.elements.filter((e) => asset.uses.some((u) => u.elementId === e.id))
    : element
      ? [element]
      : [];
  const selectNode = (id) => {
    const node = graph.nodes.find((n) => n.id === id);
    setFocus(id);
    setDetail(node);
    if (node?.type === 'asset') setAssetId(id);
    if (node?.type === 'element') {
      onElementSelect(id);
      setAssetId(null);
    }
  };
  if (!page.wiring)
    return (
      <div className="wiring-empty">
        Capture ini belum memiliki wiring tahap 3. Capture baru akan menghasilkan graph dengan
        referensi bukti; laporan lama tetap dapat dibaca.
      </div>
    );
  if (error)
    return (
      <div role="alert" className="error-banner">
        {error}
      </div>
    );
  if (!graph) return <p className="wiring-empty">Memverifikasi dan memuat artefak wiring…</p>;
  return (
    <div className="wiring-explorer">
      <div className="wiring-intro">
        <strong>Wiring berbasis bukti</strong>
        <span>
          Capture {page.captureId.slice(0, 8)} · {graph.assets.length} aset · {graph.nodes.length}{' '}
          node. Memuat paling banyak 80 node sekitar pilihan.
        </span>
      </div>
      <div className="wiring-controls">
        <label>
          Elemen wiring
          <select
            aria-label="Elemen wiring"
            value={element?.id || ''}
            onChange={(e) => {
              onElementSelect(e.target.value);
              setFocus(e.target.value);
              setAssetId(null);
              setDetail(null);
            }}
          >
            {page.elements.map((el) => (
              <option key={el.id} value={el.id}>
                {el.ordinal} · {el.selector} · {el.label.slice(0, 50)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Halaman aset
          <select
            aria-label="Halaman aset"
            value={page.id}
            onChange={(event) => onPageSelect(event.target.value)}
          >
            {job.pages.map((p) => (
              <option key={p.id} value={p.id}>
                {p.url}
              </option>
            ))}
          </select>
        </label>
        <span>Inventaris dimuat per capture halaman yang dipilih.</span>
      </div>
      <div className="wiring-columns">
        <aside className="wiring-inventory">
          <h3>Inventaris aset</h3>
          <input
            aria-label="Cari aset"
            placeholder="URL, selector, deklarasi…"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setCount(40);
            }}
          />
          <label className="wiring-element-filter">
            <input
              type="checkbox"
              checked={onlyElement}
              onChange={(e) => {
                setOnlyElement(e.target.checked);
                setCount(40);
              }}
            />
            Hanya aset elemen pilihan
          </label>
          <div className="wiring-filters">
            <select
              aria-label="Tipe aset"
              value={type}
              onChange={(e) => {
                setType(e.target.value);
                setCount(40);
              }}
            >
              <option value="">Semua tipe</option>
              {[...new Set(graph.assets.map((a) => a.type))].sort().map((t) => (
                <option key={t}>{t}</option>
              ))}
            </select>
            <select
              aria-label="Domain aset"
              value={domain}
              onChange={(e) => {
                setDomain(e.target.value);
                setCount(40);
              }}
            >
              <option value="">Semua domain</option>
              {[...new Set(graph.assets.map((a) => a.source.domain || '(inline / data)'))]
                .sort()
                .map((d) => (
                  <option key={d}>{d}</option>
                ))}
            </select>
          </div>
          <p>{visibleAssets.length} cocok · URL/query sensitif disamarkan.</p>
          <div className="wiring-asset-list">
            {visibleAssets.slice(0, count).map((a) => (
              <button
                key={a.id}
                data-asset-id={a.id}
                aria-pressed={assetId === a.id}
                className={assetId === a.id ? 'selected' : ''}
                onClick={() => selectNode(a.id)}
              >
                <strong>
                  {a.type} · {a.source.kind}
                </strong>
                <span>{a.source.url || a.uses[0].declaration}</span>
                <small>
                  {a.status} · {new Set(a.uses.map((u) => u.elementId)).size} elemen
                </small>
              </button>
            ))}
          </div>
          {visibleAssets.length > count && (
            <button className="button secondary" onClick={() => setCount(count + 40)}>
              Muat 40 aset lagi
            </button>
          )}
        </aside>
        <section className="wiring-main">
          <div className="wiring-legend">
            {Object.entries(colors).map(([label, color]) => (
              <span key={label} style={{ color }}>
                {label}
              </span>
            ))}
          </div>
          <div className="wiring-flow" data-testid="wiring-graph">
            <ReactFlow
              key={`${page.captureId}:${focus}`}
              nodes={flow.nodes}
              edges={flow.edges}
              fitView
              minZoom={0.15}
              maxZoom={1.5}
              nodesDraggable={false}
              onNodeClick={(_, n) => selectNode(n.id)}
              onEdgeClick={(_, e) => setDetail(graph.edges.find((x) => x.id === e.id))}
            >
              <Background />
              <Controls showInteractive={false} />
            </ReactFlow>
          </div>
          <div className="wiring-inspector" aria-label="Detail relasi wiring">
            {detail ? (
              <>
                <strong>
                  {detail.label || 'Relasi graph'} · {detail.relation}
                </strong>
                <p>{detail.reason}</p>
                {detail.limitation && <p>Batas: {detail.limitation}</p>}
                {detail.evidence?.map((r, i) => (
                  <a key={i} href={artifactUrl(job, r.artifactId)} target="_blank" rel="noreferrer">
                    Bukti {r.artifactId.slice(0, 8)} · {r.pointer}
                  </a>
                ))}
                {detail.details && (
                  <details>
                    <summary>Metadata yang dikumpulkan</summary>
                    <pre>{JSON.stringify(detail.details, null, 2).slice(0, 25000)}</pre>
                  </details>
                )}
              </>
            ) : (
              <p>
                Pilih node atau garis untuk alasan, batas keyakinan, metadata, dan sumber bukti.
              </p>
            )}
          </div>
          {asset && (
            <div className="wiring-uses">
              <strong>Elemen pemakai / deklarasi</strong>
              {[...new Set(asset.uses.map((u) => u.elementId))].map((id) => (
                <button
                  key={id}
                  onClick={() => {
                    onElementSelect(id);
                    setFocus(id);
                    setAssetId(null);
                  }}
                >
                  {page.elements.find((e) => e.id === id)?.selector}
                </button>
              ))}
              <strong>Request sumber yang sama</strong>
              {asset.requestIds.length ? (
                asset.requestIds.map((id) => (
                  <button key={id} onClick={() => selectNode(id)}>
                    {graph.nodes.find((n) => n.id === id)?.label}
                  </button>
                ))
              ) : (
                <p>
                  Tidak ada request cocok dalam jendela koleksi. Deklarasi/performance entry tidak
                  dijadikan request.
                </p>
              )}
            </div>
          )}
          <details className="wiring-coverage">
            <summary>Batas pengamatan & cakupan</summary>
            <pre>
              {JSON.stringify(
                { coverage: graph.coverage, gaps: graph.gaps, limits: graph.limits },
                null,
                2,
              )}
            </pre>
          </details>
        </section>
        <aside className="wiring-preview">
          <h3>Preview aman</h3>
          <p>
            Screenshot PNG terverifikasi, dengan penanda elemen. Tidak memuat ulang URL aset atau
            mengeksekusi SVG/script. Perbedaan posisi dapat terjadi pada DOM dinamis.
          </p>
          <ScreenshotCrop job={job} page={page} element={selectedElements[0]} />
          {page.screenshotArtifactId ? (
            <div className="wiring-screenshot">
              <img
                src={artifactUrl(job, page.screenshotArtifactId)}
                alt="Preview screenshot capture terverifikasi"
              />
              {selectedElements
                .filter(
                  (e) =>
                    e.bounds.y < page.screenshotHeight && e.bounds.width > 0 && e.bounds.height > 0,
                )
                .map((e) => (
                  <button
                    key={e.id}
                    aria-label={`Sorot ${e.selector}`}
                    className="wiring-highlight"
                    style={{
                      left: `${(100 * e.bounds.x) / page.screenshotWidth}%`,
                      top: `${(100 * e.bounds.y) / page.screenshotHeight}%`,
                      width: `${Math.min(100, (100 * e.bounds.width) / page.screenshotWidth)}%`,
                      height: `${(100 * e.bounds.height) / page.screenshotHeight}%`,
                    }}
                    onClick={() => {
                      onElementSelect(e.id);
                      setFocus(e.id);
                      setAssetId(null);
                    }}
                  />
                ))}
            </div>
          ) : (
            <p>Screenshot tidak tersedia.</p>
          )}
          {selectedElements.length > 0 &&
            !selectedElements.some(
              (e) =>
                e.bounds.y < page.screenshotHeight && e.bounds.width > 0 && e.bounds.height > 0,
            ) && <p>Elemen tidak terlihat atau berada di luar batas screenshot.</p>}
        </aside>
      </div>
    </div>
  );
}
