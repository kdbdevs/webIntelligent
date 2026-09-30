import { useWorkspace, WorkspaceMenu, WorkspaceGuide } from './Workspaces';
import { CaseManager, EvidencePanel } from './CaseEvidence';
import { AuthSession } from './AuthSession';
import { WiringExplorer } from './WiringExplorer';
import { SecurityFindings } from './SecurityFindings';
const ReportWorkspace = React.lazy(() =>
  import('./ReportWorkspace').then((m) => ({ default: m.ReportWorkspace })),
);
const ForensicWorkspace = React.lazy(() =>
  import('./ForensicWorkspace').then((m) => ({ default: m.ForensicWorkspace })),
);
import React, { useEffect, useMemo, useState, useRef } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  Handle,
  Position,
  MarkerType,
  applyNodeChanges,
  applyEdgeChanges,
} from '@xyflow/react';
import {
  Waypoints,
  ArrowUpRight,
  ArrowRight,
  Globe2,
  Search,
  Play,
  Square,
  PanelTop,
  MousePointer2,
  Network,
  GitBranch,
  Code2,
  ChevronRight,
  ChevronDown,
  Check,
  CircleHelp,
  Loader2,
  Download,
  ExternalLink,
  CircleDot,
  ScanLine,
  Layers3,
  Clock3,
  AlertTriangle,
  X,
  RefreshCw,
  Radio,
  ShieldCheck,
  Menu,
  Hash,
  TextCursorInput,
  Braces,
} from 'lucide-react';

const icons = {
  input: TextCursorInput,
  button: MousePointer2,
  a: ArrowUpRight,
  select: ChevronDown,
  textarea: TextCursorInput,
};
const busyStatus = (status) => ['queued', 'running'].includes(status);
const shortPath = (value) => {
  try {
    const u = new URL(value);
    return u.pathname + (u.search ? '?…' : '');
  } catch {
    return value || '/';
  }
};
const hostname = (value) => {
  try {
    return new URL(value).host;
  } catch {
    return value || '';
  }
};
const prettyTime = (value) =>
  new Date(value).toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit' });
async function api(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...options.headers },
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request gagal (${response.status})`);
  return data;
}
function Evidence({ kind = 'observed', children }) {
  return (
    <span className={`evidence ${kind}`}>
      {kind === 'observed' ? (
        <CircleDot size={10} />
      ) : kind === 'unknown' ? (
        <CircleHelp size={11} />
      ) : (
        <Code2 size={11} />
      )}
      {children ||
        {
          observed: 'Teramati',
          declared: 'Deklarasi HTML',
          correlated: 'Korelasi',
          inferred: 'Dugaan',
          unknown: 'Belum diketahui',
        }[kind]}
    </span>
  );
}
function Property({ label, children }) {
  return (
    <div className="property">
      <dt>{label}</dt>
      <dd>{children || <span className="muted">Belum diketahui</span>}</dd>
    </div>
  );
}
function Empty({ icon: Icon = Search, title, children }) {
  return (
    <div className="empty">
      <Icon size={27} strokeWidth={1.4} />
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}
function EvidenceLinks({ refs }) {
  return refs?.length ? (
    <div className="graph-evidence-links">
      {refs.map((r, i) => (
        <a
          key={i}
          href={`/api/cases/${r.caseId}/runs/${r.runId}/artifacts/${r.artifactId}/content`}
          target="_blank"
          rel="noreferrer"
        >
          Bukti {r.artifactId.slice(0, 8)} · {r.pointer}
        </a>
      ))}
    </div>
  ) : (
    <p className="muted small">Referensi per-capture tidak tersedia pada graph legacy ini.</p>
  );
}
function captureRefs(job, page, pointer = '/') {
  return page?.extractionArtifactId
    ? [
        {
          caseId: job.caseId,
          runId: job.id,
          artifactId: page.extractionArtifactId,
          captureId: page.captureId || null,
          pointer,
        },
      ]
    : [];
}
function FlowCard({ data, selected }) {
  return (
    <div className={`flow-card ${data.kind || 'observed'} ${selected ? 'selected' : ''}`}>
      <Handle type="target" position={data.targetPosition || Position.Left} />
      <span className="node-eyebrow">{data.eyebrow || 'HALAMAN'}</span>
      <strong>{data.title}</strong>
      <code>{data.detail}</code>
      <Evidence kind={data.kind || 'observed'} />
      <Handle type="source" position={data.sourcePosition || Position.Right} />
    </div>
  );
}
const nodeTypes = { card: FlowCard };
function FlowCanvas({ graph, onSelect, graphKey }) {
  const [nodes, setNodes] = useState(graph.nodes),
    [edges, setEdges] = useState(graph.edges);
  useEffect(() => {
    setNodes(graph.nodes);
    setEdges(graph.edges);
  }, [graph]);
  return (
    <div className="flow-canvas">
      <ReactFlow
        key={graphKey}
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={(changes) => setNodes((old) => applyNodeChanges(changes, old))}
        onEdgesChange={(changes) => setEdges((old) => applyEdgeChanges(changes, old))}
        onNodeClick={(_, node) => onSelect(node.data)}
        onEdgeClick={(_, edge) =>
          onSelect(
            edge.data || {
              title: 'Relasi',
              kind: 'unknown',
              explanation: 'Referensi detail tidak tersedia pada graph legacy ini.',
            },
          )
        }
        nodesConnectable={false}
        edgesReconnectable={false}
        fitView
        fitViewOptions={{ padding: 0.16 }}
        minZoom={0.3}
        maxZoom={1.6}
        colorMode="light"
      >
        <Background gap={23} size={1} color="#cbd8d2" />
        <Controls showInteractive={false} />
      </ReactFlow>
      <div className="canvas-caption">
        <MousePointer2 size={12} /> Geser canvas · klik node untuk detail
      </div>
    </div>
  );
}
function edge(id, source, target, label, kind = 'observed') {
  return {
    id,
    source,
    target,
    label,
    relation: kind,
    data: {
      title: label,
      kind,
      explanation:
        kind === 'correlated'
          ? 'Kecocokan nama/waktu; kausalitas belum terbukti.'
          : kind === 'unknown'
            ? 'Jalur internal tidak diobservasi.'
            : kind === 'declared'
              ? 'Deklarasi, bukan bukti bahwa aksi terjadi.'
              : 'Metadata browser teramati.',
    },
    type: 'smoothstep',
    markerEnd: { type: MarkerType.ArrowClosed, color: kind === 'unknown' ? '#94a29b' : '#558978' },
    style: {
      stroke: kind === 'unknown' ? '#94a29b' : '#558978',
      strokeWidth: 1.5,
      strokeDasharray: ['unknown', 'correlated', 'inferred'].includes(kind) ? '5 5' : undefined,
    },
    labelStyle: { fontSize: 10, fill: '#50695f' },
    labelBgStyle: { fill: '#f6f9f7' },
  };
}
function relatedRequests(job, page, element) {
  if (!element) return [];
  return job.requests.filter((r) => {
    const samePage = page.captureId
      ? r.frameId === page.frameId && r.documentEpoch === page.documentEpoch
      : r.pageId === page.id || r.pageUrl === page.url;
    const exactEvent =
      (page.captureId
        ? r.event?.documentId === page.documentId && r.event?.domNodeId === element.domNodeId
        : r.event?.selector === element.selector) ||
      (element.form && r.event?.formSelector === element.form.selector);
    const parameterMatch = element.name && r.body.fields.some((f) => f.name === element.name);
    return samePage && (exactEvent || parameterMatch);
  });
}
function makeDataGraph(element, requests, job, page) {
  if (!element) return { nodes: [], edges: [] };
  const request = requests
    .filter((r) => ['fetch', 'xhr', 'document'].includes(r.resourceType))
    .at(-1);
  const direct = element.listeners.filter((l) =>
    ['input', 'change', 'click', 'submit'].includes(l.event),
  );
  const form = element.form;
  const names = request?.body.fields.map((f) => f.name) || form?.fields.map((f) => f.name) || [];
  const items = [
    {
      id: 'element',
      eyebrow: '01 / ELEMEN',
      title: element.label,
      detail: element.name ? `name="${element.name}"` : element.selector,
      kind: 'observed',
      explanation: `Elemen ${element.tag} ditemukan pada DOM. Selector: ${element.selector}. Nilai input tidak dikumpulkan.`,
    },
    {
      id: 'handler',
      eyebrow: '02 / PENANGKAP EVENT',
      title: direct[0]?.handler || 'Handler belum teridentifikasi',
      detail: direct.length
        ? direct.map((l) => l.event).join(', ')
        : 'Delegasi / binding framework mungkin digunakan',
      kind: direct.length ? 'observed' : 'unknown',
      explanation: direct.length
        ? 'Nama listener langsung atau property handler teramati. Nama yang terlihat belum menjelaskan seluruh isi fungsi.'
        : 'Tidak ada handler langsung yang teridentifikasi. Listener ancestor dapat memakai event delegation; pemetaan pasti memerlukan sumber kode atau tracing tambahan.',
    },
    {
      id: 'state',
      eyebrow: '03 / STATE',
      title: 'Penyimpanan nilai',
      detail: 'React state / DOM / store?',
      kind: 'unknown',
      explanation:
        'Scan tidak dapat menyimpulkan nama React state, store, atau transformasi nilai hanya dari DOM. Data ini sengaja tidak ditebak.',
    },
    {
      id: 'payload',
      eyebrow: '04 / PARAMETER',
      title: request
        ? request.body.format
        : form
          ? 'Field form yang dideklarasikan'
          : 'Payload belum teramati',
      detail: names.slice(0, 5).join(', ') || 'Belum ada field request',
      kind: request ? 'observed' : form ? 'declared' : 'unknown',
      explanation: request
        ? 'Nama dan tipe parameter benar-benar teramati pada request. Nilai mentah tidak disimpan.'
        : 'Field HTML tidak menjamin payload aktual: JavaScript dapat memilih, mengubah, atau membatalkan data yang dikirim.',
    },
    {
      id: 'request',
      eyebrow: '05 / METHOD & TUJUAN',
      title: request
        ? `${request.method} ${shortPath(request.url)}`
        : form
          ? `${form.method} ${shortPath(form.action)}`
          : element.href
            ? shortPath(element.href)
            : 'Request belum teramati',
      detail:
        request?.contentType || (form ? form.enctype : 'Rekam interaksi untuk melihat request'),
      kind: request ? 'observed' : form || element.href ? 'declared' : 'unknown',
      explanation: request
        ? `${request.blocked ? 'Request dicoba tetapi diblokir: ' + request.blocked : 'Request teramati di browser.'} Korelasi dengan elemen berdasarkan event terbaru atau kesamaan nama parameter; bukan bukti aliran data penuh.`
        : 'Ini deklarasi HTML. Handler JavaScript dapat mengganti method, URL, dan payload. Gunakan sesi rekam untuk verifikasi.',
    },
    {
      id: 'server',
      eyebrow: '06 / PENERIMA SERVER',
      title: 'Handler internal belum diketahui',
      detail: request ? shortPath(request.url) : 'Controller / request parser',
      kind: 'unknown',
      explanation:
        'Browser dapat membuktikan endpoint dan respons, tetapi tidak mengungkap controller, request.json(), req.body, validator, atau query database internal. Hubungkan source code / server instrumentation untuk bukti tersebut.',
    },
    {
      id: 'response',
      eyebrow: '07 / RESPONS',
      title: request?.status
        ? `HTTP ${request.status}`
        : request?.blocked
          ? 'Diblokir scan pasif'
          : request?.failure
            ? 'Request gagal'
            : 'Respons belum teramati',
      detail: request?.responseType || 'Status dan content type',
      kind:
        request && (request.status || request.failure || request.blocked) ? 'observed' : 'unknown',
      explanation: request?.status
        ? `Respons server HTTP ${request.status}; body respons tidak disimpan. Status sukses sendiri tidak membuktikan perubahan database.`
        : 'Belum ada respons yang dapat diverifikasi untuk elemen ini.',
    },
  ];
  const positions = [
    { x: 0, y: 0 },
    { x: 285, y: 0 },
    { x: 570, y: 0 },
    { x: 570, y: 230 },
    { x: 285, y: 230 },
    { x: 0, y: 230 },
    { x: 0, y: 460 },
  ];
  const handles = [
    {},
    {},
    { sourcePosition: Position.Bottom },
    { targetPosition: Position.Top, sourcePosition: Position.Left },
    { targetPosition: Position.Right, sourcePosition: Position.Left },
    { targetPosition: Position.Right, sourcePosition: Position.Bottom },
    { targetPosition: Position.Top },
  ];
  const refs = captureRefs(
    job,
    page,
    `/elements/${page.elements.findIndex((el) => el.id === element.id)}`,
  );
  const requestRefs = page.observationsArtifactId
    ? [
        {
          caseId: job.caseId,
          runId: job.id,
          artifactId: page.observationsArtifactId,
          captureId: page.captureId,
          pointer: '/requests',
        },
      ]
    : refs;
  return {
    nodes: items.map((item, i) => ({
      id: item.id,
      type: 'card',
      position: positions[i],
      data: {
        ...item,
        ...handles[i],
        evidence:
          ['payload', 'request', 'response'].includes(item.id) && request ? requestRefs : refs,
      },
    })),
    edges: items
      .slice(1)
      .map((item, i) =>
        edge(
          `d${i}`,
          items[i].id,
          item.id,
          [
            'event',
            'belum terlacak',
            'submit',
            request ? 'request teramati' : 'deklarasi',
            'endpoint',
            'respons',
          ][i],
          [1, 2, 4, 5].includes(i) ? 'unknown' : request ? 'correlated' : 'declared',
        ),
      )
      .map((e) => ({
        ...e,
        evidence: [...refs, ...requestRefs],
        data: {
          ...e.data,
          evidence: [...refs, ...requestRefs],
          explanation:
            e.data.explanation +
            ' Ringkasan ini tidak membuktikan seluruh alur eksekusi; lihat Wiring & aset untuk relasi per kejadian.',
        },
      })),
  };
}
function ElementInspector({ element, page, job, onTrace }) {
  if (!element)
    return (
      <Empty icon={MousePointer2} title="Pilih satu elemen">
        Klik penanda pada screenshot atau pilih dari daftar.
      </Empty>
    );
  const requests = relatedRequests(job, page, element);
  return (
    <div className="inspector-content">
      <div className="panel-kicker">
        ELEMENT INSPECTOR <Evidence />
      </div>
      <h2>{element.label}</h2>
      <code className="selector">{element.selector}</code>
      <dl>
        <Property label="URL halaman">
          <code>{shortPath(page.url)}</code>
        </Property>
        <Property label="Tipe / nama">
          <code>
            {element.tag} · {element.type}
            {element.name ? ` · name="${element.name}"` : ''}
          </code>
        </Property>
        {element.href && (
          <Property label="Tujuan link">
            <code>{element.href}</code>
            <Evidence kind="declared" />
          </Property>
        )}
        <Property label="Penangkap langsung">
          {element.listeners.length
            ? element.listeners.map((l, i) => (
                <code className="code-line" key={i}>
                  {l.event} → {l.handler}
                </code>
              ))
            : 'Belum teridentifikasi'}
        </Property>
        <Property label="Form induk">
          <code>{element.form?.selector || 'Tidak terhubung ke form'}</code>
        </Property>
        {element.form && (
          <>
            <Property label="Method & action HTML">
              <code>
                {element.form.method} {element.form.action}
              </code>
              <Evidence kind="declared" />
            </Property>
            <Property label="Enctype">
              <code>{element.form.enctype}</code>
            </Property>
            <Property label="Nama field form">
              <div className="tokens">
                {element.form.fields.map((f, i) => (
                  <code key={i}>
                    {f.name}
                    <small>{f.type}</small>
                  </code>
                ))}
              </div>
            </Property>
          </>
        )}
      </dl>
      <button className="button primary full" onClick={onTrace}>
        <GitBranch size={15} /> Telusuri alur data <ArrowRight size={15} />
      </button>
      <div className="info-note">
        <CircleHelp size={15} />
        <span>
          {requests.length
            ? `${requests.length} request terkait secara temporal / nama parameter. Periksa bukti di Alur data.`
            : 'Belum ada request terkait yang teramati. Rekam interaksi untuk menguji input atau submit secara manual.'}
        </span>
      </div>
      {element.delegated.length > 0 && (
        <details>
          <summary>Listener ancestor ({element.delegated.length})</summary>
          <p className="muted small">
            Dapat menangani event lewat delegasi; belum terbukti sebagai handler elemen ini.
          </p>
          {element.delegated.map((l, i) => (
            <div className="listener" key={i}>
              <strong>
                {l.event} → {l.handler}
              </strong>
              <code>{l.owner}</code>
            </div>
          ))}
        </details>
      )}
    </div>
  );
}
function RequestInspector({ request }) {
  if (!request)
    return (
      <Empty icon={Network} title="Pilih request">
        Lihat method, URL, parameter, dan pemicu yang teramati.
      </Empty>
    );
  return (
    <div className="inspector-content">
      <div className="panel-kicker">
        REQUEST INSPECTOR <Evidence />
      </div>
      <h2>
        {request.method} <span className="muted">{request.status || '—'}</span>
      </h2>
      <code className="selector">{request.url}</code>
      <dl>
        <Property label="Transport / tipe">
          <code>{request.initiator?.transport || request.resourceType}</code>
        </Property>
        <Property label="Request Content-Type">
          <code>{request.contentType || '(tidak ada)'}</code>
        </Property>
        <Property label="Format body">
          <code>{request.body.format}</code>
        </Property>
        <Property label="Body parameters">
          {request.body.fields.length ? (
            <div className="tokens">
              {request.body.fields.map((f, i) => (
                <code key={i}>
                  {f.name}
                  <small>{f.type}</small>
                </code>
              ))}
            </div>
          ) : (
            '(tidak terdeteksi)'
          )}
        </Property>
        <Property label="Query parameters">
          <code>{request.queryParameters.join(', ') || '(tidak ada)'}</code>
        </Property>
        <Property label="Waktu / durasi">
          <code>
            {prettyTime(request.startedAt)} · {request.duration ?? '…'} ms
          </code>
        </Property>
        <Property label="Response Content-Type">
          <code>{request.responseType || '(belum teramati)'}</code>
        </Property>
      </dl>
      {request.blocked && (
        <div className="info-note warning">
          <ShieldCheck size={15} />
          {request.blocked}
        </div>
      )}
      {request.failure && !request.blocked && (
        <div className="info-note warning">{request.failure}</div>
      )}
      {request.event && (
        <section className="subsection">
          <h3>Event yang berdekatan</h3>
          <code>
            {request.event.type} → {request.event.selector}
          </code>
          <p className="muted small">Korelasi dalam 1,5 detik. Bukan bukti kausalitas.</p>
        </section>
      )}
      {request.initiator?.stack && (
        <details>
          <summary>Initiator stack dari browser</summary>
          <pre>{request.initiator.stack}</pre>
        </details>
      )}
      <div className="info-note">
        <CircleHelp size={15} />
        <span>
          Receiver internal server, validator, dan database belum diketahui. Nama parameter
          teramati; nilainya tidak disimpan.
        </span>
      </div>
    </div>
  );
}

export default function App() {
  const { workspace, choose, config: workspaceConfig, visited } = useWorkspace();
  const workspaceHeading = useRef(null);
  const professional = workspace !== 'learn';
  const visitedProfessional = professional || visited.has('cyber') || visited.has('lab');
  const visitedLab = workspace === 'lab' || visited.has('lab');
  const WorkspaceIcon = workspaceConfig.icon;
  const [url, setUrl] = useState(''),
    [maxPages, setMaxPages] = useState(4),
    [allowLocal, setAllowLocal] = useState(false);
  const [cases, setCases] = useState([]),
    [caseId, setCaseId] = useState(null);
  const refreshCases = () => api('/api/cases').then(setCases);
  const [history, setHistory] = useState([]),
    [job, setJob] = useState(null),
    [pageId, setPageId] = useState(null),
    [elementId, setElementId] = useState(null);
  const [tab, setTab] = useState('elements'),
    [requestId, setRequestId] = useState(null),
    [apiOnly, setApiOnly] = useState(true);
  const [error, setError] = useState(''),
    [pending, setPending] = useState(false),
    [filter, setFilter] = useState(''),
    [graphDetail, setGraphDetail] = useState(null),
    [mobileNav, setMobileNav] = useState(false);
  const chooseWorkspace = (id) => {
    choose(id);
    setMobileNav(false);
  };
  useEffect(() => {
    workspaceHeading.current?.focus({ preventScroll: true });
    window.scrollTo({ top: 0, behavior: 'instant' });
    setMobileNav(false);
  }, [workspace]);
  const [capturedRequests, setCapturedRequests] = useState(null);
  const page = job?.pages.find((p) => p.id === pageId) || job?.pages[0];
  const element = page?.elements.find((e) => e.id === elementId) || page?.elements[0];
  const isRunning = job && busyStatus(job.status),
    recording = !!job?.session;
  useEffect(() => {
    let active = true;
    setCapturedRequests(null);
    if (page?.observationsArtifactId) {
      const artifactId = page.observationsArtifactId;
      api(`/api/cases/${job.caseId}/runs/${job.id}/artifacts/${artifactId}/content`)
        .then((data) => active && setCapturedRequests({ artifactId, requests: data.requests }))
        .catch((error) => active && setError(error.message));
    }
    return () => {
      active = false;
    };
  }, [job?.caseId, job?.id, page?.observationsArtifactId]);
  // Graph references must describe the frozen capture, not later traffic in the active run.
  const graphJob = useMemo(
    () =>
      page?.observationsArtifactId
        ? {
            ...job,
            requests:
              capturedRequests?.artifactId === page.observationsArtifactId
                ? capturedRequests.requests
                : [],
          }
        : job,
    [job, page?.observationsArtifactId, capturedRequests],
  );
  const refreshHistory = () =>
    api('/api/audits')
      .then(setHistory)
      .catch(() => {});
  useEffect(() => {
    refreshHistory();
    refreshCases().catch((e) => setError(e.message));
    api('/api/health')
      .then((health) => {
        if (health.migrationWarnings?.length)
          setError(`Sebagian riwayat belum diimpor: ${health.migrationWarnings.join('; ')}`);
      })
      .catch(() => {});
  }, []);
  useEffect(() => {
    if (!job?.id || (!busyStatus(job.status) && !job.session)) return;
    let stopped = false;
    const timer = setInterval(async () => {
      try {
        const updated = await api(`/api/audits/${job.id}`);
        if (!stopped) {
          setJob(updated);
          if (!busyStatus(updated.status)) refreshHistory();
        }
      } catch (e) {
        if (!stopped) setError(e.message);
      }
    }, 1400);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [job?.id, job?.status, !!job?.session]);
  const action = async (fn) => {
    setPending(true);
    setError('');
    try {
      await fn();
    } catch (e) {
      setError(e.message);
    } finally {
      setPending(false);
    }
  };
  const start = (target = url, local = allowLocal) =>
    action(async () => {
      const created = await api('/api/audits', {
        method: 'POST',
        body: JSON.stringify({
          url: target,
          caseId: caseId || undefined,
          maxPages,
          allowLocal: local,
        }),
      });
      setJob(created);
      setCaseId(created.caseId);
      await refreshCases();
      setPageId(null);
      setElementId(null);
      setRequestId(null);
      setGraphDetail(null);
      setTab('elements');
      setFilter('');
      refreshHistory();
    });
  const selectAudit = (id) =>
    action(async () => {
      const selected = await api(`/api/audits/${id}`);
      setJob(selected);
      setCaseId(selected.caseId);
      setUrl(selected.url);
      setAllowLocal(selected.allowLocal);
      setPageId(null);
      setElementId(null);
      setGraphDetail(null);
      setMobileNav(false);
    });
  const selectPage = (id) => {
    setPageId(id);
    setElementId(null);
    setGraphDetail(null);
    setFilter('');
  };
  const sessionAction = (endpoint) =>
    action(async () => {
      const updated = await api(`/api/audits/${job.id}/${endpoint}`, {
        method: 'POST',
        body: JSON.stringify({ pageId: page?.id }),
      });
      setJob(updated);
      refreshHistory();
    });
  const authenticatedAction = (endpoint, body = {}) =>
    action(async () => {
      const updated = await api(`/api/sessions/${job.id}/${endpoint}`, {
        method: 'POST',
        body: JSON.stringify(body),
      });
      setJob(updated);
      refreshHistory();
    });
  const openAuthenticated = (options) =>
    action(async () => {
      const created = await api('/api/sessions', {
        method: 'POST',
        body: JSON.stringify({ ...options, caseId, url, maxPages, allowLocal }),
      });
      setJob(created);
      setPageId(null);
      setElementId(null);
      setRequestId(null);
      setGraphDetail(null);
      setTab('elements');
      refreshHistory();
    });
  const requests = useMemo(
    () => (graphJob && page ? relatedRequests(graphJob, page, element) : []),
    [graphJob, page, element],
  );
  const dataGraph = useMemo(
    () => makeDataGraph(element, requests, job, page),
    [element, requests, job, page],
  );
  const routeGraph = useMemo(() => {
    if (!job) return { nodes: [], edges: [] };
    const urls = job.pages.map((p) => p.url);
    const origin = job.pages[0] ? new URL(job.pages[0].url).origin : '';
    for (const e of job.edges)
      if (!urls.includes(e.to) && urls.length < 22 && e.to.startsWith(origin + '/'))
        urls.push(e.to);
    const nodes = urls.map((u, i) => {
      const p = job.pages.find((p) => p.url === u);
      const declarationPage = p || job.pages.find((x) => x.links?.some((l) => l.href === u));
      return {
        id: `route${i}`,
        type: 'card',
        position: { x: (i % 3) * 310, y: Math.floor(i / 3) * 230 },
        data: {
          title: shortPath(u),
          detail: p?.title || 'Link ditemukan · belum dipindai',
          kind: p ? 'observed' : 'declared',
          eyebrow: p ? `${p.elements.length} ELEMEN · HTTP ${p.httpStatus || '—'}` : 'URL TUJUAN',
          pageId: p?.id,
          url: u,
          evidence: captureRefs(job, declarationPage, p ? '/url' : '/links'),
          explanation: p
            ? `Snapshot ${p.elements.length} elemen dari ${u}. Klik Buka halaman untuk inspect.`
            : 'URL ada dalam href sebuah link. Halaman ini belum dibuka oleh crawler.',
        },
      };
    });
    const edges = job.edges
      .filter((e) => urls.includes(e.from) && urls.includes(e.to) && e.from !== e.to)
      .slice(0, 80)
      .map((e, i) => {
        const item = edge(
          `routeedge${i}`,
          `route${urls.indexOf(e.from)}`,
          `route${urls.indexOf(e.to)}`,
          e.label.slice(0, 24),
          'declared',
        );
        const refs = captureRefs(
          job,
          job.pages.find((p) => p.url === e.from),
          '/links',
        );
        return {
          ...item,
          evidence: refs,
          data: {
            ...item.data,
            evidence: refs,
            explanation:
              'Href dideklarasikan pada halaman sumber. URL tersensor dapat mengelompokkan variasi query/fragmen; lihat capture wiring untuk identitas elemen.',
          },
        };
      });
    return { nodes, edges };
  }, [job?.pages, job?.edges]);
  const network = (job?.requests || []).filter(
    (r) => !apiOnly || ['fetch', 'xhr'].includes(r.resourceType),
  );
  const selectedRequest = job?.requests.find((r) => r.id === requestId) || network.at(-1);
  const visibleElements = (page?.elements || []).filter((e) =>
    `${e.label} ${e.selector} ${e.name || ''} ${e.tag}`
      .toLowerCase()
      .includes(filter.toLowerCase()),
  );
  const totalElements = job?.pages.reduce((sum, p) => sum + p.elements.length, 0) || 0;

  return (
    <div className="app-shell">
      {mobileNav && (
        <button
          className="nav-backdrop"
          aria-label="Tutup navigasi"
          onClick={() => setMobileNav(false)}
        />
      )}
      <aside className={`sidebar ${mobileNav ? 'open' : ''}`}>
        <button
          className="icon-button sidebar-close"
          aria-label="Tutup sidebar"
          onClick={() => setMobileNav(false)}
        >
          <X size={17} />
        </button>
        <a
          className="brand"
          href="/"
          onClick={(e) => {
            e.preventDefault();
            chooseWorkspace('learn');
          }}
        >
          <span className="brand-symbol">
            <Waypoints size={23} />
          </span>
          <div>
            web<span>intelligent</span>
            <small>WEBSITE AUDIT WORKSPACE</small>
          </div>
        </a>
        <div className="sidebar-section">
          <span className="eyebrow">WORKSPACE</span>
          <WorkspaceMenu workspace={workspace} onSelect={chooseWorkspace} />
        </div>
        <div className="history-heading">
          <span className="eyebrow">AUDIT TERAKHIR</span>
          <button
            className="icon-button"
            aria-label="Refresh riwayat audit"
            onClick={refreshHistory}
          >
            <RefreshCw size={13} />
          </button>
        </div>
        <div className="history">
          {history.length ? (
            history
              .filter((h) => !caseId || h.caseId === caseId)
              .slice(0, 30)
              .map((h) => (
                <button
                  className={`history-item ${job?.id === h.id ? 'active' : ''}`}
                  disabled={pending || isRunning || recording}
                  key={h.id}
                  onClick={() => selectAudit(h.id)}
                >
                  <span className={`status-dot ${h.status}`} />
                  <span>
                    <strong>{hostname(h.url)}</strong>
                    <small>
                      {['record', 'authenticated'].includes(h.mode) ? 'Sesi · ' : ''}
                      {h.legacy ? 'Legacy · ' : ''}
                      {h.pageCount} halaman · {prettyTime(h.createdAt)}
                    </small>
                  </span>
                  <ChevronRight size={13} />
                </button>
              ))
          ) : (
            <p className="history-empty">Audit pertama lo akan tersimpan di sini.</p>
          )}
        </div>
        <div className="sidebar-bottom">
          <div className="local-indicator">
            <span /> Berjalan lokal
          </div>
          <p>Data audit tersimpan di komputer ini.</p>
          <code>v1.6 / Case Reports</code>
        </div>
      </aside>
      <main className="main">
        <header className="topbar">
          <div className="breadcrumbs">
            <button
              className="icon-button mobile-menu"
              aria-label="Buka sidebar"
              onClick={() => setMobileNav(!mobileNav)}
            >
              <Menu size={18} />
            </button>
            <span>Workspace</span>
            <ChevronRight size={13} />
            <strong>{workspaceConfig.title}</strong>
          </div>
          <div className="local-pill">
            <span /> LOCAL APP
          </div>
        </header>
        <div className="workspace-head">
          <div>
            <div className="eyebrow">{workspaceConfig.eyebrow}</div>
            <h1 ref={workspaceHeading} tabIndex={-1}>
              {workspaceConfig.title}
              <span>.</span>
            </h1>
            <p>{workspaceConfig.description}</p>
          </div>
          <div className="head-mark">
            <WorkspaceIcon size={42} strokeWidth={1.1} />
          </div>
        </div>
        <WorkspaceGuide
          workspace={workspace}
          hasCapture={!!page}
          onChoose={chooseWorkspace}
          onExplore={(next) => {
            setTab(next);
            setGraphDetail(null);
            requestAnimationFrame(() =>
              document
                .querySelector('.audit-workbench')
                ?.scrollIntoView({ block: 'start', behavior: 'smooth' }),
            );
          }}
        />
        <CaseManager
          cases={cases}
          selectedId={caseId}
          disabled={pending || isRunning || recording}
          onError={setError}
          onSelect={(id) => {
            setCaseId(id);
            setJob(null);
            setError('');
          }}
          onSaved={async (c) => {
            await refreshCases();
            setCaseId(c.id);
            if (job?.caseId !== c.id) setJob(null);
          }}
        />
        <div className="workspace-section" hidden={workspace !== 'lab'}>
          {visitedLab && (
            <React.Suspense fallback={<p>Memuat workspace forensik…</p>}>
              <ForensicWorkspace
                key={caseId || 'no-case'}
                caseId={caseId}
                operator={cases.find((c) => c.id === caseId)?.operator}
                disabled={pending || isRunning || recording}
              />
            </React.Suspense>
          )}
        </div>
        <div className="workspace-section" hidden={!professional}>
          {visitedProfessional && (
            <React.Suspense fallback={<p>Memuat pelaporan…</p>}>
              <ReportWorkspace
                key={caseId || 'report-no-case'}
                caseId={caseId}
                operator={cases.find((c) => c.id === caseId)?.operator}
                disabled={pending || isRunning || recording}
              />
            </React.Suspense>
          )}
        </div>
        <section className="scan-box" aria-label="Mulai audit website">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              start();
            }}
          >
            <Globe2 size={19} />
            <input
              aria-label="URL website yang akan diaudit"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://website-yang-mau-diaudit.com"
              required
              disabled={pending || isRunning || recording}
              spellCheck={false}
            />
            <button className="button primary" disabled={pending || isRunning || recording}>
              {pending || isRunning ? (
                <Loader2 size={16} className="spin" />
              ) : (
                <ScanLine size={16} />
              )}
              <span>{recording ? 'Sesi aktif' : isRunning ? 'Memindai…' : 'Audit website'}</span>
              <ArrowRight size={16} />
            </button>
          </form>
          <div className="scan-options">
            <label>
              Maks. halaman{' '}
              <select
                value={maxPages}
                onChange={(e) => setMaxPages(Number(e.target.value))}
                disabled={isRunning || recording}
              >
                <option value="1">1 halaman</option>
                <option value="4">4 halaman</option>
                <option value="7">7 halaman</option>
                <option value="10">10 halaman</option>
              </select>
            </label>
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={allowLocal}
                onChange={(e) => setAllowLocal(e.target.checked)}
                disabled={isRunning || recording}
              />{' '}
              Izinkan localhost
            </label>
            <span className="scan-passive">
              <ShieldCheck size={13} /> Scan pasif · form tidak disubmit
            </span>
          </div>
        </section>
        <div className="workspace-section" hidden={!professional && !recording}>
          <AuthSession
            job={job}
            caseId={caseId}
            scope={cases.find((c) => c.id === caseId)?.scope.navigation}
            disabled={pending || isRunning || recording}
            pending={pending}
            onOpen={openAuthenticated}
            onAction={authenticatedAction}
          />
        </div>
        {error && (
          <div className="error-banner" role="alert">
            <AlertTriangle size={17} />
            <span>{error}</span>
            <button className="icon-button" aria-label="Tutup error" onClick={() => setError('')}>
              <X size={16} />
            </button>
          </div>
        )}
        {!job ? (
          <section className="welcome">
            <div className="welcome-top">
              <span className="eyebrow">A WEBSITE IS MORE THAN A SCREEN</span>
              <h2>
                Dari tampilan,
                <br />
                sampai ke mana datanya pergi.
              </h2>
              <p>
                Masukkan URL untuk memetakan elemen interaktif, tujuan navigasi, deklarasi form, dan
                trafik browser yang benar-benar teramati.
              </p>
            </div>
            <div className="welcome-flow">
              <div>
                <span className="welcome-icon">
                  <MousePointer2 size={22} />
                </span>
                <small>01 / ELEMEN</small>
                <strong>Input & interaksi</strong>
                <code>email · button · link</code>
              </div>
              <ArrowRight className="welcome-arrow" size={21} />
              <div>
                <span className="welcome-icon">
                  <Network size={22} />
                </span>
                <small>02 / REQUEST</small>
                <strong>Method & parameter</strong>
                <code>POST · JSON · field names</code>
              </div>
              <ArrowRight className="welcome-arrow" size={21} />
              <div>
                <span className="welcome-icon">
                  <Waypoints size={22} />
                </span>
                <small>03 / KONEKSI</small>
                <strong>URL & alur halaman</strong>
                <code>/login → /dashboard</code>
              </div>
            </div>
            <div className="demo-callout">
              <div>
                <strong>Coba dengan website demo lokal.</strong>
                <p>Form login, navigasi, dan endpoint sungguhan. Tanpa akun.</p>
              </div>
              <button
                className="button secondary"
                disabled={pending}
                onClick={() => {
                  const target = `${location.origin}/demo`;
                  setUrl(target);
                  setAllowLocal(true);
                  start(target, true);
                }}
              >
                Audit demo <ArrowUpRight size={15} />
              </button>
            </div>
          </section>
        ) : (
          <>
            <div className="audit-summary">
              <div className="audit-title">
                <span className={`status-orb ${job.status}`}>
                  {isRunning ? (
                    <Loader2 className="spin" size={18} />
                  ) : job.status === 'complete' ? (
                    <Check size={18} />
                  ) : (
                    <AlertTriangle size={18} />
                  )}
                </span>
                <div>
                  <h2>{hostname(job.url)}</h2>
                  <span>{job.message}</span>
                </div>
              </div>
              <div className="audit-counts">
                <span>
                  <strong>{job.pages.length}</strong> halaman
                </span>
                <span>
                  <strong>{totalElements}</strong> elemen
                </span>
                <span>
                  <strong>{job.requests.length}</strong> request
                </span>
              </div>
              <div className="audit-actions">
                {isRunning ? (
                  <button
                    className="button secondary small-button"
                    onClick={() =>
                      action(async () => {
                        await api(`/api/audits/${job.id}/cancel`, { method: 'POST' });
                        setJob(await api(`/api/audits/${job.id}`));
                      })
                    }
                  >
                    <Square size={13} /> Hentikan
                  </button>
                ) : (
                  <a
                    className="button secondary small-button"
                    href={`/api/audits/${job.id}/export`}
                    download
                  >
                    <Download size={14} /> JSON
                  </a>
                )}
              </div>
            </div>
            <div className="workspace-section" hidden={!professional}>
              {visitedProfessional && (
                <>
                  <EvidencePanel job={job} onError={setError} />
                  <SecurityFindings key={job.id} job={job} />
                </>
              )}
            </div>
            {job.warnings.length > 0 && (
              <details className="warnings">
                <summary>
                  <AlertTriangle size={14} />
                  {job.warnings.length} catatan audit
                </summary>
                {job.warnings.map((w, i) => (
                  <p key={i}>{w}</p>
                ))}
              </details>
            )}
            {page ? (
              <section className="audit-workbench">
                <div className="workbench-toolbar">
                  <div className="view-tabs">
                    {[
                      ['elements', MousePointer2, 'Elemen'],
                      ['routes', GitBranch, 'Alur halaman'],
                      ['data', Braces, 'Alur data'],
                      ['network', Network, 'Network'],
                      ['wiring', Layers3, 'Wiring & aset'],
                    ].map(([id, Icon, title]) => (
                      <button
                        key={id}
                        className={tab === id ? 'active' : ''}
                        aria-pressed={tab === id}
                        onClick={() => {
                          setTab(id);
                          setGraphDetail(null);
                        }}
                      >
                        <Icon size={14} />
                        {title}
                      </button>
                    ))}
                  </div>
                  <div className="record-actions">
                    {job.mode !== 'authenticated' && (
                      <button
                        className="button secondary small-button"
                        disabled={pending || isRunning}
                        onClick={() => sessionAction('record')}
                      >
                        <Play size={13} /> Rekam interaksi
                      </button>
                    )}
                  </div>
                </div>
                <div className="page-strip">
                  <label>
                    <PanelTop size={14} />
                    <select
                      aria-label="Halaman audit"
                      value={page.id}
                      onChange={(e) => selectPage(e.target.value)}
                    >
                      {job.pages.map((p) => (
                        <option key={p.id} value={p.id}>
                          {shortPath(p.url)} — {p.title || 'Untitled'}
                        </option>
                      ))}
                    </select>
                  </label>
                  <span>
                    {page.elements.length} elemen · snapshot {prettyTime(page.capturedAt)}
                  </span>
                  <a
                    href={page.url}
                    target="_blank"
                    rel="noreferrer"
                    className="icon-button"
                    aria-label="Buka halaman asal"
                  >
                    <ExternalLink size={13} />
                  </a>
                </div>
                {page.warnings.length > 0 && (
                  <div className="page-notes">{page.warnings.join(' ')}</div>
                )}
                {tab === 'wiring' && (
                  <WiringExplorer
                    job={job}
                    page={page}
                    element={element}
                    onElementSelect={setElementId}
                    onPageSelect={selectPage}
                  />
                )}
                {tab === 'elements' && (
                  <div className="elements-layout">
                    <div className="elements-list">
                      <div className="element-search">
                        <Search size={14} />
                        <input
                          aria-label="Cari elemen"
                          value={filter}
                          onChange={(e) => setFilter(e.target.value)}
                          placeholder="Cari elemen…"
                        />
                      </div>
                      <div className="element-list-scroll">
                        {visibleElements.length ? (
                          visibleElements.map((el) => {
                            const Icon = icons[el.tag] || MousePointer2;
                            return (
                              <button
                                key={el.id}
                                className={`element-row ${element?.id === el.id ? 'selected' : ''}`}
                                onClick={() => setElementId(el.id)}
                              >
                                <Icon size={14} />
                                <span>
                                  <strong>{el.label}</strong>
                                  <code>{el.name ? `name=${el.name}` : el.tag}</code>
                                </span>
                                <small>
                                  {String(el.ordinal || el.id.slice(1)).padStart(2, '0')}
                                </small>
                              </button>
                            );
                          })
                        ) : (
                          <p className="list-empty">Tidak ada elemen yang cocok.</p>
                        )}
                      </div>
                    </div>
                    <div className="snapshot-panel">
                      <div className="panel-label">
                        <span>PAGE SNAPSHOT</span>
                        <span>
                          <MousePointer2 size={11} /> Klik penanda
                        </span>
                      </div>
                      {page.screenshot ? (
                        <div className="screenshot-scroll">
                          <div className="screenshot-image">
                            <img src={page.screenshot} alt={`Screenshot halaman ${page.url}`} />
                            <div className="screenshot-markers">
                              {page.elements
                                .filter((el) => el.bounds.y < page.screenshotHeight)
                                .map((el) => (
                                  <button
                                    aria-label={`Pilih elemen ${el.label}`}
                                    key={el.id}
                                    className={`element-marker ${element?.id === el.id ? 'selected' : ''}`}
                                    style={{
                                      left: `${(100 * el.bounds.x) / page.screenshotWidth}%`,
                                      top: `${(100 * el.bounds.y) / page.screenshotHeight}%`,
                                      width: `${Math.min(100, (100 * el.bounds.width) / page.screenshotWidth)}%`,
                                      height: `${(100 * el.bounds.height) / page.screenshotHeight}%`,
                                    }}
                                    onClick={() => setElementId(el.id)}
                                  >
                                    <span>{el.ordinal || el.id.slice(1)}</span>
                                  </button>
                                ))}
                            </div>
                          </div>
                        </div>
                      ) : (
                        <Empty icon={PanelTop} title="Screenshot belum tersedia">
                          Gunakan daftar elemen untuk inspect.
                        </Empty>
                      )}
                    </div>
                    <aside className="detail-panel">
                      <ElementInspector
                        element={element}
                        job={graphJob}
                        page={page}
                        onTrace={() => {
                          setTab('data');
                          setGraphDetail(null);
                        }}
                      />
                    </aside>
                  </div>
                )}
                {tab === 'routes' && (
                  <div className="graph-layout">
                    <FlowCanvas
                      graph={routeGraph}
                      graphKey={job.id + '-routes'}
                      onSelect={setGraphDetail}
                    />
                    <aside className="detail-panel">
                      <div className="inspector-content">
                        <div className="panel-kicker">NAVIGATION MAP</div>
                        <h2>{graphDetail?.title || 'Peta navigasi'}</h2>
                        <p>
                          {graphDetail?.explanation ||
                            'Setiap node adalah URL. Garis menunjukkan link href yang ditemukan; bukan klaim bahwa navigasi sudah dijalankan.'}
                        </p>
                        {graphDetail?.url && <code className="selector">{graphDetail.url}</code>}
                        {graphDetail && <EvidenceLinks refs={graphDetail.evidence} />}
                        {graphDetail?.pageId && (
                          <button
                            className="button primary full"
                            onClick={() => {
                              selectPage(graphDetail.pageId);
                              setTab('elements');
                            }}
                          >
                            Buka halaman <ArrowRight size={14} />
                          </button>
                        )}
                        <div className="legend">
                          <Evidence>Halaman dipindai</Evidence>
                          <Evidence kind="declared">Link belum dipindai</Evidence>
                        </div>
                        <p className="muted small">
                          Peta dibatasi 22 URL dan 80 koneksi agar tetap terbaca. Laporan JSON
                          menyimpan link yang ditemukan sampai batas audit.
                        </p>
                      </div>
                    </aside>
                  </div>
                )}
                {tab === 'data' && (
                  <>
                    <div className="data-context">
                      <label>
                        Telusuri elemen{' '}
                        <select
                          aria-label="Elemen untuk alur data"
                          value={element?.id || ''}
                          onChange={(e) => {
                            setElementId(e.target.value);
                            setGraphDetail(null);
                          }}
                        >
                          {page.elements.map((el) => (
                            <option key={el.id} value={el.id}>
                              {el.label} {el.name ? `(${el.name})` : ''}
                            </option>
                          ))}
                        </select>
                      </label>
                      <span>
                        {requests.length} request terkait · korelasi, bukan bukti kausalitas
                      </span>
                    </div>
                    {element ? (
                      <div className="graph-layout">
                        <FlowCanvas
                          graph={dataGraph}
                          graphKey={`${page.id}-${element.id}`}
                          onSelect={setGraphDetail}
                        />
                        <aside className="detail-panel">
                          <div className="inspector-content">
                            <div className="panel-kicker">DATA FLOW INSPECTOR</div>
                            <h2>{graphDetail?.title || element.label}</h2>
                            {graphDetail ? (
                              <>
                                <Evidence kind={graphDetail.kind} />
                                <p>{graphDetail.explanation}</p>
                                <code className="selector">{graphDetail.detail}</code>
                                <EvidenceLinks refs={graphDetail.evidence} />
                              </>
                            ) : (
                              <>
                                <p>
                                  Klik node untuk melihat siapa menangkap data, method, parameter,
                                  dan batas bukti yang tersedia.
                                </p>
                                <div className="legend">
                                  <Evidence />
                                  <Evidence kind="declared" />
                                  <Evidence kind="unknown" />
                                </div>
                                <div className="info-note">
                                  <CircleHelp size={15} /> State framework dan handler backend
                                  sengaja ditandai belum diketahui.
                                </div>
                              </>
                            )}
                            {requests.length > 0 && (
                              <section className="subsection">
                                <h3>Request terkait</h3>
                                {requests.slice(-8).map((r) => (
                                  <button
                                    className="linked-request"
                                    key={r.id}
                                    onClick={() => {
                                      setRequestId(r.id);
                                      setApiOnly(false);
                                      setTab('network');
                                    }}
                                  >
                                    <span className={`method ${r.method.toLowerCase()}`}>
                                      {r.method}
                                    </span>
                                    <code>{shortPath(r.url)}</code>
                                    <ArrowUpRight size={13} />
                                  </button>
                                ))}
                              </section>
                            )}
                          </div>
                        </aside>
                      </div>
                    ) : (
                      <Empty title="Tidak ada elemen">
                        Pilih halaman lain untuk menelusuri alur data.
                      </Empty>
                    )}
                  </>
                )}
                {tab === 'network' && (
                  <div className="network-layout">
                    <div className="network-main">
                      <div className="network-tools">
                        <span>{network.length} request teramati</span>
                        <label className="checkbox-label">
                          <input
                            type="checkbox"
                            checked={apiOnly}
                            onChange={(e) => setApiOnly(e.target.checked)}
                          />{' '}
                          Hanya fetch / XHR
                        </label>
                      </div>
                      <div className="request-table-wrap">
                        {network.length ? (
                          <table className="request-table">
                            <thead>
                              <tr>
                                <th>Method</th>
                                <th>Endpoint</th>
                                <th>Status</th>
                                <th>Parameter</th>
                              </tr>
                            </thead>
                            <tbody>
                              {network.map((r) => (
                                <tr
                                  key={r.id}
                                  className={selectedRequest?.id === r.id ? 'selected' : ''}
                                >
                                  <td>
                                    <span className={`method ${r.method.toLowerCase()}`}>
                                      {r.method}
                                    </span>
                                  </td>
                                  <td>
                                    <button onClick={() => setRequestId(r.id)}>
                                      <strong>{shortPath(r.url)}</strong>
                                      <span>
                                        {hostname(r.url)} · {r.resourceType}
                                        {r.mode === 'record' ? ' · REC' : ''}
                                      </span>
                                    </button>
                                  </td>
                                  <td>
                                    <span className={`http-status ${r.status >= 400 ? 'bad' : ''}`}>
                                      {r.blocked
                                        ? 'Blocked'
                                        : r.status || (r.failure ? 'Failed' : '…')}
                                    </span>
                                  </td>
                                  <td>
                                    <code>
                                      {r.body.fields
                                        .map((f) => f.name)
                                        .slice(0, 3)
                                        .join(', ') ||
                                        r.queryParameters.slice(0, 3).join(', ') ||
                                        '—'}
                                    </code>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        ) : (
                          <Empty icon={Network} title="Belum ada request API">
                            Coba tampilkan semua request atau gunakan Rekam interaksi untuk mencoba
                            form.
                          </Empty>
                        )}
                      </div>
                      {job.events.length > 0 && (
                        <section className="events-section">
                          <h3>
                            Interaksi terbaru <span>{job.events.length}</span>
                          </h3>
                          {job.events
                            .slice(-6)
                            .reverse()
                            .map((e) => (
                              <div className="event-row" key={e.id}>
                                <small>{prettyTime(e.at)}</small>
                                <code>{e.type}</code>
                                <span>{e.selector}</span>
                              </div>
                            ))}
                        </section>
                      )}
                    </div>
                    <aside className="detail-panel">
                      <RequestInspector request={selectedRequest} />
                    </aside>
                  </div>
                )}
              </section>
            ) : (
              <div className="loading-stage">
                {isRunning ? (
                  <>
                    <div className="scan-animation">
                      <ScanLine size={38} strokeWidth={1.2} />
                    </div>
                    <h3>Membaca website lewat browser…</h3>
                    <p>Snapshot pertama akan muncul setelah halaman dimuat.</p>
                  </>
                ) : (
                  <Empty icon={AlertTriangle} title="Belum ada halaman yang berhasil dipetakan">
                    Periksa catatan audit di atas, lalu coba URL lain.
                  </Empty>
                )}
              </div>
            )}
          </>
        )}
        <footer className="workspace-footer">
          <span>
            <ShieldCheck size={13} /> Bukti browser, bukan tebakan backend.
          </span>
          <span>Playwright + React Flow</span>
        </footer>
      </main>
    </div>
  );
}
