import React, { useEffect, useMemo, useState } from 'react';
import { Activity, ShieldAlert, Target, Network, RefreshCw, DatabaseZap } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const INITIAL_METRICS = {
  risk_score: 0,
  active_alarms: 0,
  critical_incidents: 0,
  ai_agent_status: 'Monitoring',
  points: [{ time: '00:00', packets: 0, alerts: 0, load: 0 }],
};

const DEMO_SCENARIOS = [
  { id: 'mixed', label: 'Mixed Demo' },
  { id: 'firewall_misconfig', label: 'Firewall Misconfig' },
  { id: 'ddos_attack', label: 'DDoS Attack' },
  { id: 'routing_failure', label: 'Routing Failure' },
];

async function apiRequest(path, options = {}) {
  const response = await fetch(path, {
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    ...options,
  });

  if (!response.ok) {
    let detail = 'Request failed';
    try {
      const payload = await response.json();
      detail = payload.detail || payload.message || detail;
    } catch {
      detail = response.statusText || detail;
    }
    throw new Error(detail);
  }

  return response.json();
}

function formatTimestamp(value) {
  if (!value) return 'N/A';
  return new Date(value).toLocaleString();
}

function buildGraphLayout(graph) {
  const nodes = graph?.nodes || [];
  const edges = (graph?.edges || []).filter(Boolean);

  if (!nodes.length) {
    return { nodes: [], edges: [], width: 780, height: 260 };
  }

  const nodeById = new Map(nodes.map((node) => [node.id, node]));
  const relationshipPriority = {
    event_pattern: 3,
    same_device: 2,
    shared_resource: 1,
  };
  const filteredEdges = Array.from(
    edges.reduce((grouped, edge) => {
      if (!grouped.has(edge.source)) {
        grouped.set(edge.source, []);
      }
      grouped.get(edge.source).push(edge);
      return grouped;
    }, new Map()).entries(),
  ).flatMap(([, sourceEdges]) =>
    sourceEdges
      .sort((left, right) => {
        const priorityDiff = (relationshipPriority[right.relationship] || 0) - (relationshipPriority[left.relationship] || 0);
        if (priorityDiff !== 0) {
          return priorityDiff;
        }

        const leftTarget = nodeById.get(left.target);
        const rightTarget = nodeById.get(right.target);
        return new Date(leftTarget?.timestamp || 0) - new Date(rightTarget?.timestamp || 0);
      })
      .slice(0, 2),
  );

  const incoming = new Map(nodes.map((node) => [node.id, 0]));
  const outgoing = new Map(nodes.map((node) => [node.id, 0]));
  const adjacency = new Map(nodes.map((node) => [node.id, []]));

  filteredEdges.forEach((edge) => {
    incoming.set(edge.target, (incoming.get(edge.target) || 0) + 1);
    outgoing.set(edge.source, (outgoing.get(edge.source) || 0) + 1);
    adjacency.get(edge.source)?.push(edge.target);
  });

  const queue = nodes
    .filter((node) => (incoming.get(node.id) || 0) === 0)
    .sort((left, right) => new Date(left.timestamp) - new Date(right.timestamp));

  const levels = new Map();
  queue.forEach((node) => levels.set(node.id, 0));

  while (queue.length) {
    const current = queue.shift();
    const currentLevel = levels.get(current.id) || 0;

    (adjacency.get(current.id) || []).forEach((nextId) => {
      const nextLevel = Math.max(levels.get(nextId) ?? 0, currentLevel + 1);
      const previousLevel = levels.get(nextId);
      levels.set(nextId, nextLevel);
      if (previousLevel !== nextLevel) {
        const nextNode = nodes.find((node) => node.id === nextId);
        if (nextNode) {
          queue.push(nextNode);
        }
      }
    });
  }

  nodes.forEach((node) => {
    if (!levels.has(node.id)) {
      levels.set(node.id, 0);
    }
  });

  const columns = new Map();
  nodes.forEach((node) => {
    const level = levels.get(node.id) || 0;
    if (!columns.has(level)) {
      columns.set(level, []);
    }
    columns.get(level).push(node);
  });

  const orderedColumns = [...columns.entries()].sort((left, right) => left[0] - right[0]);
  const laneOrder = ['config_change', 'traffic_blocked', 'syn_flood', 'latency_spike', 'auth_failure', 'service_failure'];
  const laneIndex = (eventType) => {
    const index = laneOrder.indexOf(eventType);
    return index === -1 ? laneOrder.length : index;
  };

  orderedColumns.forEach(([, columnNodes]) => {
    columnNodes.sort((left, right) => {
      const laneDiff = laneIndex(left.event_type) - laneIndex(right.event_type);
      if (laneDiff !== 0) {
        return laneDiff;
      }
      return new Date(left.timestamp) - new Date(right.timestamp);
    });
  });

  const nodeWidth = 168;
  const nodeHeight = 68;
  const columnGap = 220;
  const rowGap = 100;
  const leftPadding = 120;
  const topPadding = 70;
  const maxRows = Math.max(...orderedColumns.map(([, columnNodes]) => columnNodes.length));
  const width = Math.max(860, leftPadding * 2 + (orderedColumns.length - 1) * columnGap + nodeWidth);
  const height = Math.max(320, topPadding * 2 + (maxRows - 1) * rowGap + nodeHeight);

  const positionedNodes = orderedColumns.flatMap(([level, columnNodes]) =>
    columnNodes.map((node, rowIndex) => ({
      ...node,
      x: leftPadding + level * columnGap,
      y: topPadding + rowIndex * rowGap,
      width: nodeWidth,
      height: nodeHeight,
      downstreamCount: outgoing.get(node.id) || 0,
      upstreamCount: incoming.get(node.id) || 0,
    })),
  );

  const nodeLookup = new Map(positionedNodes.map((node) => [node.id, node]));
  const positionedEdges = filteredEdges
    .map((edge) => {
      const source = nodeLookup.get(edge.source);
      const target = nodeLookup.get(edge.target);
      if (!source || !target) {
        return null;
      }

      const startX = source.x + source.width;
      const startY = source.y + source.height / 2;
      const endX = target.x;
      const endY = target.y + target.height / 2;
      const controlOffset = Math.max(36, (endX - startX) / 2);

      return {
        ...edge,
        path: `M ${startX} ${startY} C ${startX + controlOffset} ${startY}, ${endX - controlOffset} ${endY}, ${endX} ${endY}`,
        labelX: (startX + endX) / 2,
        labelY: (startY + endY) / 2 - 10,
      };
    })
    .filter(Boolean);

  return {
    nodes: positionedNodes,
    edges: positionedEdges,
    width,
    height,
  };
}

function GraphView({ graph }) {
  if (!graph?.nodes?.length) {
    return <p className="empty-state">No causal graph available yet.</p>;
  }

  const layout = buildGraphLayout(graph);

  return (
    <div className="graph-wrap">
      <svg viewBox={`0 0 ${layout.width} ${layout.height}`} className="graph-svg" role="img" aria-label="Causal RCA graph">
        <defs>
          <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
            <polygon points="0 0, 10 3.5, 0 7" fill="#00f3ff" />
          </marker>
        </defs>

        {layout.edges.map((edge) => (
          <g key={`${edge.source}-${edge.target}`}>
            <path
              d={edge.path}
              fill="none"
              stroke={edge.relationship === 'event_pattern' ? 'rgba(0, 243, 255, 0.85)' : 'rgba(139, 148, 176, 0.5)'}
              strokeWidth={edge.relationship === 'event_pattern' ? '2.4' : '1.5'}
              markerEnd="url(#arrowhead)"
            />
            <text
              x={edge.labelX}
              y={edge.labelY}
              fill="#8b94b0"
              fontSize="10"
              textAnchor="middle"
            >
              {edge.relationship.replaceAll('_', ' ')}
            </text>
          </g>
        ))}

        {layout.nodes.map((node) => (
          <g key={node.id}>
            <rect
              x={node.x}
              y={node.y}
              width={node.width}
              height={node.height}
              rx="10"
              fill={node.is_root_cause ? 'rgba(255,0,234,0.16)' : node.is_failure ? 'rgba(255,68,68,0.16)' : 'rgba(17,21,38,0.95)'}
              stroke={node.is_root_cause ? '#ff00ea' : node.is_failure ? '#ff4444' : '#00f3ff'}
              strokeWidth="1.6"
            />
            <text x={node.x + node.width / 2} y={node.y + 18} textAnchor="middle" fill="#e2e8f0" fontSize="11" fontWeight="600">
              {node.event_type}
            </text>
            <text x={node.x + node.width / 2} y={node.y + 35} textAnchor="middle" fill="#8b94b0" fontSize="10">
              {node.source}
            </text>
            <text x={node.x + node.width / 2} y={node.y + 52} textAnchor="middle" fill="#8b94b0" fontSize="9">
              impact {node.impact_score} • out {node.downstreamCount}
            </text>
          </g>
        ))}
      </svg>
    </div>
  );
}

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [incidents, setIncidents] = useState([]);
  const [metrics, setMetrics] = useState(INITIAL_METRICS);
  const [selectedIncidentRef, setSelectedIncidentRef] = useState(null);
  const [loadingIncidents, setLoadingIncidents] = useState(true);
  const [loadingMetrics, setLoadingMetrics] = useState(true);
  const [actionMessage, setActionMessage] = useState('');
  const [error, setError] = useState('');
  const [analyzingIncidentRef, setAnalyzingIncidentRef] = useState(null);
  const [isSeeding, setIsSeeding] = useState(false);
  const [securityPosture, setSecurityPosture] = useState(null);
  const [selectedScenario, setSelectedScenario] = useState('mixed');

  const selectedIncident = useMemo(
    () => incidents.find((incident) => incident.incident_ref === selectedIncidentRef) || null,
    [incidents, selectedIncidentRef],
  );

  const fetchIncidents = async ({ silent = false } = {}) => {
    if (!silent) {
      setLoadingIncidents(true);
    }

    try {
      const data = await apiRequest('/api/incidents');
      setIncidents(data);
      setSelectedIncidentRef((current) => {
        if (current && data.some((incident) => incident.incident_ref === current)) {
          return current;
        }
        return data[0]?.incident_ref || null;
      });
      setError('');
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoadingIncidents(false);
    }
  };

  const fetchMetrics = async ({ silent = false } = {}) => {
    if (!silent) {
      setLoadingMetrics(true);
    }

    try {
      const data = await apiRequest('/api/metrics');
      setMetrics(data);
      setError('');
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoadingMetrics(false);
    }
  };

  const fetchSecurityPosture = async () => {
    try {
      const data = await apiRequest('/api/security/posture');
      setSecurityPosture(data);
    } catch (requestError) {
      setError(requestError.message);
    }
  };

  useEffect(() => {
    fetchIncidents();
    fetchMetrics();
    fetchSecurityPosture();
  }, []);

  useEffect(() => {
    const intervalId = window.setInterval(() => {
      fetchIncidents({ silent: true });
      fetchMetrics({ silent: true });
    }, 5000);

    return () => window.clearInterval(intervalId);
  }, []);

  useEffect(() => {
    if (!analyzingIncidentRef) {
      return undefined;
    }

    const intervalId = window.setInterval(async () => {
      try {
        const data = await apiRequest('/api/incidents');
        setIncidents(data);
        const analyzedIncident = data.find((incident) => incident.incident_ref === analyzingIncidentRef);
        if (analyzedIncident?.status === 'completed' || analyzedIncident?.ai_report) {
          setAnalyzingIncidentRef(null);
        }
      } catch (requestError) {
        setError(requestError.message);
      }
    }, 2500);

    return () => window.clearInterval(intervalId);
  }, [analyzingIncidentRef]);

  const refreshDashboard = async () => {
    await Promise.all([fetchIncidents(), fetchMetrics()]);
    setActionMessage('Dashboard refreshed from live backend data.');
  };

  const seedDemoData = async () => {
    if (isSeeding) {
      return;
    }

    setIsSeeding(true);
    setActionMessage(`Seeding ${selectedScenario.replaceAll('_', ' ')} scenario...`);
    setError('');
    try {
      const result = await apiRequest(`/api/seed?scenario=${encodeURIComponent(selectedScenario)}`, { method: 'POST' });
      await Promise.all([
        fetchIncidents(),
        fetchMetrics(),
      ]);
      setActionMessage(result.message);
    } catch (requestError) {
      setError(requestError.message);
      setActionMessage('');
    } finally {
      setIsSeeding(false);
    }
  };

  const triggerAIAnalysis = async (incident) => {
    setSelectedIncidentRef(incident.incident_ref);
    setActiveTab('rca');
    setAnalyzingIncidentRef(incident.incident_ref);
    setActionMessage('');

    try {
      const result = await apiRequest(`/api/analyze/${incident.incident_ref}`, { method: 'POST' });
      setActionMessage(result.message);
      await fetchIncidents({ silent: true });
      await fetchMetrics({ silent: true });
      setError('');
    } catch (requestError) {
      setAnalyzingIncidentRef(null);
      setError(requestError.message);
    }
  };

  return (
    <div className="app-container">
      <aside className="sidebar">
        <div className="logo-area" style={{ marginBottom: '3rem' }}>
          <h1>Net<span className="highlight">RCA</span> AI</h1>
          <p style={{ color: 'var(--brand-cyan)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', marginTop: '0.5rem' }}>
            v2.1.0 secure-rca
          </p>
        </div>

        <nav style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <button
            style={{ textAlign: 'left', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
            className={activeTab === 'dashboard' ? 'primary' : ''}
            onClick={() => setActiveTab('dashboard')}
          >
            <Activity size={18} /> Dashboard
          </button>
          <button
            style={{ textAlign: 'left', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
            className={activeTab === 'rca' ? 'primary' : ''}
            onClick={() => setActiveTab('rca')}
          >
            <Network size={18} /> RCA Engine
          </button>
          <button
            style={{ textAlign: 'left', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
            onClick={seedDemoData}
            disabled={isSeeding}
          >
            <DatabaseZap size={18} /> {isSeeding ? `Seeding ${selectedScenario.replaceAll('_', ' ')}...` : 'Seed Demo Logs'}
          </button>
        </nav>
      </aside>

      <main className="main-content">
        <header className="header">
          <div>
            <h2 className="title-glow" style={{ margin: 0 }}>Command Center</h2>
            <p style={{ color: 'var(--text-muted)' }}>Live backend incidents, AI RCA, and secure ingestion telemetry</p>
          </div>
          <div className="header-actions">
            <button onClick={refreshDashboard} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <RefreshCw size={16} /> Refresh
            </button>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <span className="live-indicator"></span>
              <span style={{ fontFamily: 'var(--font-mono)' }}>{metrics.ai_agent_status}</span>
            </div>
          </div>
        </header>

        {error ? <div className="notice notice-error">{error}</div> : null}
        {actionMessage ? <div className="notice notice-info">{actionMessage}</div> : null}
        {securityPosture ? (
          <div className="security-strip">
            <span>Encrypted using AES-GCM</span>
            <span>Integrity verified using SHA-512</span>
            <span>Authenticated using HMAC-SHA512</span>
            <span>TLS Ready: {securityPosture.tls.tls_ready ? 'Yes' : 'Configured for deployment'}</span>
          </div>
        ) : null}

        {activeTab === 'dashboard' && (
          <div className="scenario-strip">
            {DEMO_SCENARIOS.map((scenario) => (
              <button
                key={scenario.id}
                className={selectedScenario === scenario.id ? 'primary' : ''}
                onClick={() => setSelectedScenario(scenario.id)}
                disabled={isSeeding}
              >
                {scenario.label}
              </button>
            ))}
          </div>
        )}

        {activeTab === 'dashboard' && (
          <>
            <div className="dashboard-grid">
              <div className="panel">
                <h4 style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>Global Risk Score</h4>
                <div className="metrics-number" style={{ color: 'var(--brand-pink)', textShadow: 'var(--glow-pink)' }}>
                  {loadingMetrics ? '--' : metrics.risk_score}
                  <span style={{ fontSize: '1rem', color: 'var(--text-muted)', textShadow: 'none' }}>/100</span>
                </div>
                <div style={{ color: '#ff4444', fontSize: '0.85rem' }}>Severity-weighted from active incidents</div>
              </div>
              <div className="panel">
                <h4 style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>Active Alarms</h4>
                <div className="metrics-number">{loadingMetrics ? '--' : metrics.active_alarms}</div>
                <div style={{ color: 'var(--brand-cyan)', fontSize: '0.85rem' }}>
                  {loadingMetrics ? 'Loading...' : `${metrics.critical_incidents} critical incidents`}
                </div>
              </div>
              <div className="panel">
                <h4 style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>AI Agent Status</h4>
                <div className="metrics-number" style={{ fontSize: '1.8rem', marginTop: '0.5rem', color: 'var(--brand-purple)' }}>
                  {loadingMetrics ? 'Syncing' : metrics.ai_agent_status}
                </div>
                <div style={{ color: 'var(--brand-purple)', fontSize: '0.85rem' }}>
                  Structured RCA JSON is persisted on incident records
                </div>
              </div>
            </div>

            <div className="panel" style={{ height: '300px' }}>
              <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '1rem' }}>
                <Activity size={18} color="var(--brand-cyan)" /> Network Traffic & Alert Rate
              </h3>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={metrics.points}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="time" stroke="var(--text-muted)" />
                  <YAxis stroke="var(--text-muted)" />
                  <Tooltip contentStyle={{ backgroundColor: 'var(--bg-panel)', borderColor: 'var(--border-neon)' }} />
                  <Line type="monotone" dataKey="packets" stroke="var(--brand-cyan)" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="alerts" stroke="var(--brand-pink)" strokeWidth={2} />
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div className="panel">
              <h3 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '1rem' }}>
                <ShieldAlert size={18} color="var(--brand-pink)" /> Live Incident Feed (Correlated)
              </h3>

              {loadingIncidents ? (
                <p className="empty-state">Loading incidents from the backend...</p>
              ) : incidents.length === 0 ? (
                <p className="empty-state">No incidents yet. Use “Seed Demo Logs” to generate correlated incidents.</p>
              ) : (
                <table>
                  <thead>
                    <tr>
                      <th>Incident ID</th>
                      <th>Updated</th>
                      <th>Classification</th>
                      <th>Target Node</th>
                      <th>Severity</th>
                      <th>Status</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {incidents.map((incident) => (
                      <tr key={incident.incident_ref}>
                        <td>
                          <button className="link-button" onClick={() => { setSelectedIncidentRef(incident.incident_ref); setActiveTab('rca'); }}>
                            {incident.incident_ref}
                          </button>
                        </td>
                        <td>{formatTimestamp(incident.updated_at)}</td>
                        <td>{incident.classification}</td>
                        <td>{incident.target}</td>
                        <td>
                          <span className={`badge badge-${incident.severity}`}>{incident.severity.toUpperCase()}</span>
                        </td>
                        <td>
                          <span className={`badge badge-status-${incident.status}`}>{incident.status.toUpperCase()}</span>
                        </td>
                        <td>
                          <button
                            className="primary"
                            onClick={() => triggerAIAnalysis(incident)}
                            disabled={analyzingIncidentRef === incident.incident_ref}
                          >
                            {analyzingIncidentRef === incident.incident_ref ? 'Running...' : 'Run RCA'}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </>
        )}

        {activeTab === 'rca' && (
          <div className="panel panel-pink">
            <h2>AI Root Cause Analysis Engine</h2>
            {!selectedIncident ? (
              <p style={{ color: 'var(--text-muted)' }}>Select an incident from the dashboard to inspect its live causal chain and AI report.</p>
            ) : (
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '1rem', marginBottom: '1rem' }}>
                  <div>
                    <h3 style={{ margin: 0, color: 'var(--brand-cyan)' }}>
                      {selectedIncident.incident_ref} | {selectedIncident.classification}
                    </h3>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                      Target: {selectedIncident.target} {selectedIncident.service ? `• Service: ${selectedIncident.service}` : ''} {selectedIncident.port ? `• Port: ${selectedIncident.port}` : ''}
                    </p>
                    <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>
                      Severity score: {selectedIncident.severity_score} • Updated: {formatTimestamp(selectedIncident.updated_at)}
                    </p>
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem', alignSelf: 'flex-start' }}>
                    <span className={`badge badge-${selectedIncident.severity}`}>{selectedIncident.severity.toUpperCase()}</span>
                    <span className={`badge badge-status-${selectedIncident.status}`}>{selectedIncident.status.toUpperCase()}</span>
                  </div>
                </div>

                {['pending', 'analyzing'].includes(selectedIncident.status) && !selectedIncident.ai_report ? (
                  <div style={{ textAlign: 'center', padding: '3rem 0' }}>
                    <div
                      style={{
                        width: '50px',
                        height: '50px',
                        border: '3px solid transparent',
                        borderTopColor: 'var(--brand-pink)',
                        borderRadius: '50%',
                        animation: 'spin 1s linear infinite',
                        margin: '0 auto 1rem auto',
                      }}
                    ></div>
                    <p style={{ fontFamily: 'var(--font-mono)', color: 'var(--brand-pink)' }}>
                      AI agent is iterating through observation, hypothesis, validation, and conclusion...
                    </p>
                    <style>{'@keyframes spin { 100% { transform: rotate(360deg); } }'}</style>
                  </div>
                ) : selectedIncident.ai_report ? (
                  <div className="ai-box">
                    <h3><Target size={20} /> Structured Root Cause Report</h3>
                    <div style={{ marginTop: '1rem' }}>
                      <p><strong>Primary Cause:</strong> <span style={{ color: 'var(--brand-pink)' }}>{selectedIncident.ai_report.root_cause}</span></p>
                      <p style={{ marginTop: '0.5rem', lineHeight: '1.6' }}><strong>Explanation:</strong> {selectedIncident.ai_report.executive_summary}</p>
                      <p style={{ marginTop: '0.5rem', lineHeight: '1.6' }}><strong>Reasoning:</strong> {selectedIncident.ai_report.reasoning}</p>
                      <p style={{ marginTop: '0.5rem', lineHeight: '1.6' }}><strong>Confidence:</strong> {Math.round((selectedIncident.ai_report.confidence || 0) * 100)}%</p>

                      <div style={{ marginTop: '1.5rem', padding: '1rem', background: 'rgba(0,0,0,0.3)', borderLeft: '3px solid var(--brand-cyan)' }}>
                        <h4 style={{ color: 'var(--brand-cyan)', margin: 0, marginBottom: '0.5rem' }}>Security Impact</h4>
                        <ul className="detail-list">
                          {selectedIncident.ai_report.security_impact.map((item) => (
                            <li key={item}>{item}</li>
                          ))}
                        </ul>
                      </div>

                      <div style={{ marginTop: '1rem', padding: '1rem', background: 'rgba(0,0,0,0.3)', borderLeft: '3px solid var(--brand-pink)' }}>
                        <h4 style={{ color: 'var(--brand-pink)', margin: 0, marginBottom: '0.5rem' }}>Recommended Remediation</h4>
                        <ul className="detail-list">
                          {selectedIncident.ai_report.remediation_steps.map((item) => (
                            <li key={item}>{item}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>
                ) : (
                  <p className="empty-state">No RCA output yet. Trigger analysis from the incident feed.</p>
                )}

                <div className="rca-grid">
                  <div style={{ marginTop: '2rem' }}>
                    <h4 style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Causal Chain</h4>
                    <div className="chain-list">
                      {selectedIncident.causal_chain.map((step) => (
                        <span key={step} className="chain-pill">{step}</span>
                      ))}
                    </div>
                  </div>

                  <div style={{ marginTop: '2rem' }}>
                    <h4 style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Correlated Timeline</h4>
                    <pre className="log-box">
                      {selectedIncident.timeline.map((entry) => (
                        `[${formatTimestamp(entry.timestamp)}] ${entry.source}: ${entry.event_type} -> ${entry.observation}`
                      )).join('\n') || 'No correlated timeline available.'}
                    </pre>
                  </div>
                </div>

                <div style={{ marginTop: '2rem' }}>
                  <h4 style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Graph-Based RCA View</h4>
                  <GraphView graph={selectedIncident.graph} />
                </div>

                {selectedIncident.ai_report ? (
                  <div style={{ marginTop: '2rem' }} className="soc-report">
                    <h4 style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>SOC-Style RCA Report</h4>
                    <div className="report-grid">
                      <div className="report-card">
                        <h5>Executive Summary</h5>
                        <p>{selectedIncident.ai_report.executive_summary}</p>
                      </div>
                      <div className="report-card">
                        <h5>Root Cause</h5>
                        <p>{selectedIncident.ai_report.root_cause}</p>
                      </div>
                      <div className="report-card">
                        <h5>What Changed</h5>
                        <p>{selectedIncident.ai_report.what_changed}</p>
                      </div>
                      <div className="report-card">
                        <h5>Why It Happened</h5>
                        <p>{selectedIncident.ai_report.why_it_happened}</p>
                      </div>
                      <div className="report-card">
                        <h5>Security Impact</h5>
                        <ul className="detail-list">
                          {selectedIncident.ai_report.security_impact.map((item) => <li key={item}>{item}</li>)}
                        </ul>
                      </div>
                      <div className="report-card">
                        <h5>Risk Level</h5>
                        <p>{selectedIncident.ai_report.security_risk_level}</p>
                        <h5 style={{ marginTop: '1rem' }}>Confidence Score</h5>
                        <p>{Math.round((selectedIncident.ai_report.confidence || 0) * 100)}%</p>
                      </div>
                      <div className="report-card">
                        <h5>Affected Components</h5>
                        <ul className="detail-list">
                          {selectedIncident.ai_report.affected_components.map((item) => <li key={item}>{item}</li>)}
                        </ul>
                      </div>
                      <div className="report-card">
                        <h5>Recommended Fix</h5>
                        <p>{selectedIncident.ai_report.remediation}</p>
                      </div>
                    </div>

                    <div className="report-card" style={{ marginTop: '1rem' }}>
                      <h5>Reasoning Steps</h5>
                      <div className="audit-list">
                        {selectedIncident.ai_report.reasoning_steps.map((step) => (
                          <div key={`${step.phase}-${step.detail}`} className="audit-item">
                            <div><strong>{step.phase}</strong></div>
                            <div>{step.detail}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                ) : null}

                <div style={{ marginTop: '2rem' }}>
                  <h4 style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Security Evidence</h4>
                  <div className="security-evidence">
                    <div className="report-card">
                      <h5>Cryptography Controls</h5>
                      <ul className="detail-list">
                        <li>Encrypted using AES-GCM before log payload storage.</li>
                        <li>Integrity checked using SHA-512 hashes.</li>
                        <li>Authenticity enforced with HMAC-SHA512 when configured.</li>
                      </ul>
                    </div>
                    <div className="report-card">
                      <h5>Verification Status</h5>
                      <ul className="detail-list">
                        {selectedIncident.correlated_logs.slice(0, 5).map((log) => (
                          <li key={log.id}>
                            {log.source} / {log.event_type}: hash {log.integrity_hash?.slice(0, 16)}... / verified {log.source_verified ? 'yes' : 'no'}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>

                <div style={{ marginTop: '2rem' }}>
                  <h4 style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>Audit Trail</h4>
                  {selectedIncident.audit_trail.length === 0 ? (
                    <p className="empty-state">No audit entries recorded yet.</p>
                  ) : (
                    <div className="audit-list">
                      {selectedIncident.audit_trail.map((entry) => (
                        <div key={`${entry.action}-${entry.created_at}`} className="audit-item">
                          <div>
                            <strong>{entry.action}</strong> by {entry.actor}
                          </div>
                          <div style={{ color: 'var(--text-muted)' }}>{formatTimestamp(entry.created_at)}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
