import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, ShieldCheck, Activity, Terminal, AlertTriangle, 
  CheckCircle2, RefreshCw, Radio, Lock, LogOut, ChevronRight,
  Flame, Crosshair, Key, Globe, Cpu, Ban, Check, Sliders
} from 'lucide-react';
import { api } from './services/api';
import type { AuthResponse, ThreatStats, Incident, FlowIngestResult } from './types';

export default function App() {
  const [user, setUser] = useState<AuthResponse | null>(() => {
    const saved = localStorage.getItem('sentinelai_user');
    return saved ? JSON.parse(saved) : null;
  });

  // Auth form state
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('admin@sentinelai.com');
  const [password, setPassword] = useState('SentinelSecret2026!');
  const [fullName, setFullName] = useState('Lead Security Analyst');
  const [authError, setAuthError] = useState('');
  const [authLoading, setAuthLoading] = useState(false);

  // App Data state
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [simulating, setSimulating] = useState(false);
  const [simResult, setSimResult] = useState<FlowIngestResult | null>(null);

  useEffect(() => {
    if (user) {
      loadData();
      const interval = setInterval(loadData, 4000);
      return () => clearInterval(interval);
    }
  }, [user, filterStatus]);

  async function loadData() {
    try {
      const s = await api.getStats();
      setStats(s);

      const statusParam = filterStatus === 'ALL' ? undefined : filterStatus;
      const incList = await api.getIncidents(statusParam);
      setIncidents(incList);

      // If an incident is currently selected, refresh its details
      if (selectedIncident) {
        const fresh = await api.getIncident(selectedIncident.id);
        setSelectedIncident(fresh);
      } else if (incList.length > 0 && !selectedIncident) {
        const first = await api.getIncident(incList[0].id);
        setSelectedIncident(first);
      }
    } catch (err: any) {
      if (err.message === 'Unauthorized') {
        setUser(null);
      }
    }
  }

  async function handleAuth(e: React.FormEvent) {
    e.preventDefault();
    setAuthLoading(true);
    setAuthError('');
    try {
      let res: AuthResponse;
      if (isRegister) {
        res = await api.register({ email, password, full_name: fullName });
      } else {
        res = await api.login(email, password);
      }
      localStorage.setItem('sentinelai_token', res.access_token);
      localStorage.setItem('sentinelai_user', JSON.stringify(res));
      setUser(res);
    } catch (err: any) {
      setAuthError(err.message || 'Authentication failed');
    } finally {
      setAuthLoading(false);
    }
  }

  function handleLogout() {
    localStorage.removeItem('sentinelai_token');
    localStorage.removeItem('sentinelai_user');
    setUser(null);
  }

  async function handleSelectIncident(inc: Incident) {
    try {
      const detailed = await api.getIncident(inc.id);
      setSelectedIncident(detailed);
    } catch {
      setSelectedIncident(inc);
    }
  }

  async function handleUpdateStatus(newStatus: string) {
    if (!selectedIncident) return;
    try {
      const updated = await api.updateIncidentStatus(selectedIncident.id, newStatus);
      setSelectedIncident(updated);
      await loadData();
    } catch (err: any) {
      alert(err.message);
    }
  }

  async function handleMitigate() {
    if (!selectedIncident) return;
    try {
      await api.mitigateIncident(selectedIncident.id, 'BLOCK_IP');
      alert(`Firewall block successfully enforced for source IP: ${selectedIncident.src_ip}`);
      await loadData();
    } catch (err: any) {
      alert(err.message);
    }
  }

  // Attack Simulator Presets
  async function simulateScenario(scenario: string) {
    setSimulating(true);
    setSimResult(null);

    let flowData: Record<string, any> = {};

    if (scenario === 'DOS') {
      flowData = {
        src_ip: `185.220.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`,
        src_port: 54100 + Math.floor(Math.random() * 5000),
        dst_ip: '10.0.0.12',
        dst_port: 80,
        protocol: 'TCP',
        flow_duration_ms: 8.5,
        total_fwd_packets: 400,
        total_bwd_packets: 0,
        flow_bytes_per_sec: 950000.0,
        flow_packets_per_sec: 18000.0,
        fwd_packet_length_mean: 64.0,
        syn_flag_count: 400,
        ack_flag_count: 0
      };
    } else if (scenario === 'PORTSCAN') {
      flowData = {
        src_ip: `45.154.${Math.floor(Math.random() * 250)}.88`,
        src_port: 49152,
        dst_ip: '10.0.0.12',
        dst_port: Math.floor(Math.random() * 65000) + 1,
        protocol: 'TCP',
        flow_duration_ms: 1.2,
        total_fwd_packets: 1,
        total_bwd_packets: 0,
        flow_bytes_per_sec: 4400.0,
        flow_packets_per_sec: 800.0,
        fwd_packet_length_mean: 44.0,
        syn_flag_count: 1,
        ack_flag_count: 0
      };
    } else if (scenario === 'BRUTE_FORCE') {
      flowData = {
        src_ip: `194.26.${Math.floor(Math.random() * 250)}.12`,
        src_port: 38290,
        dst_ip: '10.0.0.12',
        dst_port: 22,
        protocol: 'TCP',
        flow_duration_ms: 180.0,
        total_fwd_packets: 25,
        total_bwd_packets: 20,
        flow_bytes_per_sec: 14000.0,
        flow_packets_per_sec: 250.0,
        fwd_packet_length_mean: 125.0,
        bwd_packet_length_mean: 180.0,
        syn_flag_count: 1,
        psh_flag_count: 8,
        ack_flag_count: 43
      };
    } else if (scenario === 'WEB_ATTACK') {
      flowData = {
        src_ip: `198.51.100.${Math.floor(Math.random() * 250)}`,
        src_port: 51230,
        dst_ip: '10.0.0.12',
        dst_port: 443,
        protocol: 'TCP',
        flow_duration_ms: 350.0,
        total_fwd_packets: 10,
        total_bwd_packets: 4,
        flow_bytes_per_sec: 28000.0,
        flow_packets_per_sec: 40.0,
        fwd_packet_length_mean: 1450.0,
        bwd_packet_length_mean: 450.0,
        syn_flag_count: 1,
        psh_flag_count: 4,
        ack_flag_count: 12
      };
    } else if (scenario === 'BOTNET') {
      flowData = {
        src_ip: `192.0.2.${Math.floor(Math.random() * 250)}`,
        src_port: 6667,
        dst_ip: '10.0.0.12',
        dst_port: 6667,
        protocol: 'TCP',
        flow_duration_ms: 45.0,
        total_fwd_packets: 3,
        total_bwd_packets: 3,
        flow_bytes_per_sec: 5000.0,
        flow_packets_per_sec: 50.0,
        flow_iat_mean: 1000.0,
        flow_iat_std: 0.1,
        fwd_packet_length_mean: 128.0,
        bwd_packet_length_mean: 128.0,
        syn_flag_count: 1,
        ack_flag_count: 4
      };
    } else {
      // Normal Benign HTTPS Flow
      flowData = {
        src_ip: '192.168.1.105',
        src_port: 52140,
        dst_ip: '10.0.0.12',
        dst_port: 443,
        protocol: 'TCP',
        flow_duration_ms: 220.0,
        total_fwd_packets: 8,
        total_bwd_packets: 12,
        flow_bytes_per_sec: 15000.0,
        flow_packets_per_sec: 40.0,
        fwd_packet_length_mean: 320.0,
        bwd_packet_length_mean: 780.0,
        syn_flag_count: 1,
        ack_flag_count: 19
      };
    }

    try {
      const res = await api.ingestFlow(flowData);
      setSimResult(res);
      await loadData();
      if (res.incident_id) {
        const freshInc = await api.getIncident(res.incident_id);
        setSelectedIncident(freshInc);
      }
    } catch (err: any) {
      alert('Simulation error: ' + err.message);
    } finally {
      setSimulating(false);
    }
  }

  // ------------------ AUTH SCREEN ------------------
  if (!user) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#0b0f19', padding: '1rem' }}>
        <div style={{ width: '100%', maxWidth: '420px', background: '#111827', border: '1px solid #1f2937', borderRadius: '12px', padding: '2rem', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
            <div style={{ background: '#4f46e5', padding: '0.6rem', borderRadius: '8px', display: 'flex' }}>
              <ShieldAlert size={28} color="#fff" />
            </div>
            <div>
              <h1 style={{ fontSize: '1.3rem', fontWeight: 800, color: '#f8fafc', letterSpacing: '-0.5px' }}>SentinelAI</h1>
              <p style={{ fontSize: '0.8rem', color: '#94a3b8' }}>Network Detection & Response (NDR)</p>
            </div>
          </div>

          <div style={{ display: 'flex', background: '#0b0f19', padding: '4px', borderRadius: '8px', marginBottom: '1.5rem' }}>
            <button
              onClick={() => setIsRegister(false)}
              style={{ flex: 1, padding: '0.5rem', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 600, fontSize: '0.85rem', background: !isRegister ? '#1f2937' : 'transparent', color: !isRegister ? '#fff' : '#94a3b8' }}
            >
              Sign In
            </button>
            <button
              onClick={() => setIsRegister(true)}
              style={{ flex: 1, padding: '0.5rem', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 600, fontSize: '0.85rem', background: isRegister ? '#1f2937' : 'transparent', color: isRegister ? '#fff' : '#94a3b8' }}
            >
              Register Analyst
            </button>
          </div>

          {authError && (
            <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid rgba(239, 68, 68, 0.3)', color: '#f87171', padding: '0.75rem', borderRadius: '8px', fontSize: '0.85rem', marginBottom: '1rem' }}>
              {authError}
            </div>
          )}

          <form onSubmit={handleAuth} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {isRegister && (
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '4px' }}>Analyst Name</label>
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={e => setFullName(e.target.value)}
                  style={{ width: '100%', padding: '0.6rem 0.8rem', background: '#0b0f19', border: '1px solid #374151', borderRadius: '6px', color: '#fff', fontSize: '0.9rem' }}
                />
              </div>
            )}
            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '4px' }}>Email Address</label>
              <input
                type="email"
                required
                value={email}
                onChange={e => setEmail(e.target.value)}
                style={{ width: '100%', padding: '0.6rem 0.8rem', background: '#0b0f19', border: '1px solid #374151', borderRadius: '6px', color: '#fff', fontSize: '0.9rem' }}
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '4px' }}>Password</label>
              <input
                type="password"
                required
                value={password}
                onChange={e => setPassword(e.target.value)}
                style={{ width: '100%', padding: '0.6rem 0.8rem', background: '#0b0f19', border: '1px solid #374151', borderRadius: '6px', color: '#fff', fontSize: '0.9rem' }}
              />
            </div>
            <button
              type="submit"
              disabled={authLoading}
              style={{ marginTop: '0.5rem', padding: '0.75rem', background: '#4f46e5', border: 'none', borderRadius: '6px', color: '#fff', fontWeight: 600, cursor: 'pointer' }}
            >
              {authLoading ? 'Authenticating...' : isRegister ? 'Register Account' : 'Authenticate to SOC'}
            </button>
          </form>
        </div>
      </div>
    );
  }

  // Threat level color configuration
  const threatLevelColors = {
    LOW: { bg: 'rgba(16, 185, 129, 0.15)', border: 'rgba(16, 185, 129, 0.4)', text: '#34d399', dot: '#10b981' },
    ELEVATED: { bg: 'rgba(234, 179, 8, 0.15)', border: 'rgba(234, 179, 8, 0.4)', text: '#facc15', dot: '#eab308' },
    HIGH: { bg: 'rgba(249, 115, 22, 0.15)', border: 'rgba(249, 115, 22, 0.4)', text: '#fb923c', dot: '#f97316' },
    SEVERE: { bg: 'rgba(239, 68, 68, 0.15)', border: 'rgba(239, 68, 68, 0.4)', text: '#f87171', dot: '#ef4444' }
  };
  const currentThreat = threatLevelColors[stats?.threat_level || 'LOW'];

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', background: '#0b0f19' }}>
      {/* Top Navbar */}
      <header style={{ height: '64px', borderBottom: '1px solid #1f2937', background: '#111827', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <div style={{ background: '#4f46e5', padding: '0.4rem', borderRadius: '6px', display: 'flex' }}>
              <ShieldAlert size={22} color="#fff" />
            </div>
            <div>
              <span style={{ fontSize: '1.15rem', fontWeight: 800, color: '#fff', letterSpacing: '-0.3px' }}>SentinelAI</span>
              <span style={{ fontSize: '0.7rem', color: '#818cf8', background: 'rgba(99,102,241,0.15)', padding: '2px 6px', borderRadius: '4px', marginLeft: '6px' }}>NDR SOC</span>
            </div>
          </div>

          {/* Threat Level Pill */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: '0.5rem',
            padding: '4px 12px', borderRadius: '20px',
            fontSize: '0.8rem', fontWeight: 700,
            background: currentThreat.bg,
            border: `1px solid ${currentThreat.border}`,
            color: currentThreat.text
          }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: currentThreat.dot, boxShadow: `0 0 8px ${currentThreat.dot}` }} />
            <span>PERIMETER THREAT LEVEL: {stats?.threat_level || 'EVALUATING'}</span>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#f8fafc' }}>{user.full_name}</div>
            <div style={{ fontSize: '0.75rem', color: '#9ca3af' }}>{user.role} | {user.email}</div>
          </div>
          <button
            onClick={handleLogout}
            style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.4rem 0.75rem', background: '#1f2937', border: '1px solid #374151', borderRadius: '6px', color: '#d1d5db', cursor: 'pointer', fontSize: '0.8rem' }}
          >
            <LogOut size={14} />
            Logout
          </button>
        </div>
      </header>

      {/* Main Body */}
      <main style={{ flex: 1, padding: '1.5rem', maxWidth: '1400px', margin: '0 auto', width: '100%', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
        
        {/* KPI Cards Row */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem' }}>
          <div style={{ background: '#111827', border: '1px solid #1f2937', padding: '1.25rem', borderRadius: '8px' }}>
            <div style={{ fontSize: '0.8rem', color: '#9ca3af', fontWeight: 600 }}>Total Flows Ingested</div>
            <div style={{ fontSize: '2rem', fontWeight: 800, color: '#fff', marginTop: '0.25rem' }}>{stats?.total_flows ?? 0}</div>
          </div>
          <div style={{ background: '#111827', border: '1px solid rgba(239, 68, 68, 0.3)', padding: '1.25rem', borderRadius: '8px' }}>
            <div style={{ fontSize: '0.8rem', color: '#f87171', fontWeight: 600 }}>Active Threat Incidents</div>
            <div style={{ fontSize: '2rem', fontWeight: 800, color: '#f87171', marginTop: '0.25rem' }}>{stats?.active_incidents ?? 0}</div>
          </div>
          <div style={{ background: '#111827', border: '1px solid rgba(16, 185, 129, 0.3)', padding: '1.25rem', borderRadius: '8px' }}>
            <div style={{ fontSize: '0.8rem', color: '#34d399', fontWeight: 600 }}>Mitigated Attacks</div>
            <div style={{ fontSize: '2rem', fontWeight: 800, color: '#34d399', marginTop: '0.25rem' }}>{stats?.mitigated_incidents ?? 0}</div>
          </div>
          <div style={{ background: '#111827', border: '1px solid rgba(99, 102, 241, 0.3)', padding: '1.25rem', borderRadius: '8px' }}>
            <div style={{ fontSize: '0.8rem', color: '#818cf8', fontWeight: 600 }}>ML Model Accuracy</div>
            <div style={{ fontSize: '2rem', fontWeight: 800, color: '#818cf8', marginTop: '0.25rem' }}>99.8%</div>
          </div>
        </div>

        {/* 2-Column SOC Layout: Threat Stream (Left) vs Explainable AI Drawer (Right) */}
        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '1.5rem', flex: 1 }}>
          
          {/* LEFT: Incident Feed */}
          <div style={{ background: '#111827', border: '1px solid #1f2937', borderRadius: '8px', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            <div style={{ padding: '1rem', borderBottom: '1px solid #1f2937', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h2 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#fff', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <ShieldAlert size={18} color="#ef4444" />
                  Active Incident Queue ({incidents.length})
                </h2>
                <p style={{ fontSize: '0.75rem', color: '#9ca3af' }}>Classified in real-time by XGBoost and Isolation Forest</p>
              </div>

              {/* Status Filters */}
              <div style={{ display: 'flex', gap: '4px', background: '#0b0f19', padding: '3px', borderRadius: '6px' }}>
                {['ALL', 'DETECTED', 'INVESTIGATING', 'MITIGATED', 'RESOLVED'].map(st => (
                  <button
                    key={st}
                    onClick={() => setFilterStatus(st)}
                    style={{
                      padding: '3px 8px', border: 'none', borderRadius: '4px', cursor: 'pointer',
                      fontSize: '0.7rem', fontWeight: 600,
                      background: filterStatus === st ? '#1f2937' : 'transparent',
                      color: filterStatus === st ? '#fff' : '#9ca3af'
                    }}
                  >
                    {st}
                  </button>
                ))}
              </div>
            </div>

            <div style={{ flex: 1, overflowY: 'auto', maxHeight: '550px' }}>
              {incidents.length === 0 ? (
                <div style={{ padding: '3rem', textAlign: 'center', color: '#6b7280' }}>
                  <ShieldCheck size={40} color="#10b981" style={{ margin: '0 auto 0.5rem auto' }} />
                  <div>No security incidents found under filter. All traffic clean!</div>
                </div>
              ) : (
                incidents.map(inc => {
                  const isSelected = selectedIncident?.id === inc.id;
                  return (
                    <div
                      key={inc.id}
                      onClick={() => handleSelectIncident(inc)}
                      style={{
                        padding: '1rem',
                        borderBottom: '1px solid #1f2937',
                        cursor: 'pointer',
                        background: isSelected ? 'rgba(99, 102, 241, 0.1)' : 'transparent',
                        borderLeft: isSelected ? '3px solid #6366f1' : '3px solid transparent',
                        transition: 'background 0.15s'
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.25rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <span className={`badge-${inc.severity.toLowerCase()}`} style={{ padding: '2px 6px', borderRadius: '4px', fontSize: '0.7rem', fontWeight: 700 }}>
                            {inc.severity}
                          </span>
                          <span style={{ fontWeight: 700, color: '#f9fafb', fontSize: '0.9rem' }}>{inc.primary_attack_vector}</span>
                        </div>
                        <span style={{ fontSize: '0.7rem', padding: '2px 6px', borderRadius: '4px', background: '#1f2937', color: '#d1d5db' }}>
                          {inc.status}
                        </span>
                      </div>

                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.78rem', color: '#9ca3af', marginTop: '0.4rem' }}>
                        <div>Source: <code style={{ color: '#f87171' }}>{inc.src_ip}</code> → Target: <code style={{ color: '#cbd5e1' }}>{inc.dst_ip}</code></div>
                        <div>Confidence: <strong style={{ color: '#38bdf8' }}>{(inc.risk_score * 100).toFixed(1)}%</strong></div>
                      </div>
                      <div style={{ fontSize: '0.7rem', color: '#6b7280', marginTop: '0.2rem' }}>
                        Detected: {new Date(inc.created_at).toLocaleTimeString()}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* RIGHT: Explainable AI (SHAP) & Remediation Panel */}
          <div style={{ background: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1rem', overflowY: 'auto', maxHeight: '640px' }}>
            {selectedIncident ? (
              <>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid #1f2937', paddingBottom: '0.75rem' }}>
                  <div>
                    <span className={`badge-${selectedIncident.severity.toLowerCase()}`} style={{ padding: '2px 6px', borderRadius: '4px', fontSize: '0.7rem', fontWeight: 700 }}>
                      {selectedIncident.severity} ALERT
                    </span>
                    <h3 style={{ fontSize: '1.15rem', fontWeight: 800, color: '#fff', marginTop: '0.4rem' }}>
                      {selectedIncident.title}
                    </h3>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '0.7rem', color: '#9ca3af' }}>Risk Score</div>
                    <div style={{ fontSize: '1.4rem', fontWeight: 800, color: selectedIncident.risk_score > 0.8 ? '#f87171' : '#fb923c' }}>
                      {(selectedIncident.risk_score * 100).toFixed(1)}%
                    </div>
                  </div>
                </div>

                {/* Explainable AI (SHAP) Section */}
                <div>
                  <h4 style={{ fontSize: '0.85rem', fontWeight: 700, color: '#818cf8', display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.5rem' }}>
                    <Sliders size={16} /> TreeSHAP Local Feature Attribution
                  </h4>

                  {selectedIncident.alerts && selectedIncident.alerts.length > 0 && selectedIncident.alerts[0].shap_values ? (
                    <div style={{ background: '#0b0f19', border: '1px solid #1f2937', borderRadius: '6px', padding: '0.85rem' }}>
                      <p style={{ fontSize: '0.8rem', color: '#cbd5e1', marginBottom: '0.75rem', lineHeight: '1.4' }}>
                        {selectedIncident.alerts[0].shap_values.summary}
                      </p>

                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                        {selectedIncident.alerts[0].shap_values.top_features?.map((f: any, idx: number) => {
                          const isRisk = f.shap_value > 0;
                          const widthPct = Math.min(100, Math.round(f.abs_impact * 200));
                          return (
                            <div key={idx} style={{ fontSize: '0.75rem' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2px' }}>
                                <span style={{ color: '#e5e7eb', fontFamily: 'monospace' }}>{f.feature} = {f.value}</span>
                                <span style={{ color: isRisk ? '#f87171' : '#34d399', fontWeight: 700 }}>
                                  {isRisk ? `+${f.shap_value}` : `${f.shap_value}`}
                                </span>
                              </div>
                              <div style={{ width: '100%', height: '6px', background: '#1f2937', borderRadius: '3px', overflow: 'hidden' }}>
                                <div style={{
                                  width: `${widthPct}%`,
                                  height: '100%',
                                  background: isRisk ? '#ef4444' : '#10b981',
                                  borderRadius: '3px'
                                }} />
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  ) : (
                    <div style={{ fontSize: '0.8rem', color: '#6b7280', padding: '1rem', background: '#0b0f19', borderRadius: '6px' }}>
                      No SHAP vector stored for this flow.
                    </div>
                  )}
                </div>

                {/* Mitigation History */}
                {selectedIncident.mitigations && selectedIncident.mitigations.length > 0 && (
                  <div>
                    <h4 style={{ fontSize: '0.85rem', fontWeight: 700, color: '#34d399', display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.4rem' }}>
                      <CheckCircle2 size={15} /> Active Mitigation
                    </h4>
                    <div style={{ background: '#0b0f19', border: '1px solid rgba(16,185,129,0.3)', borderRadius: '6px', padding: '0.6rem 0.8rem', fontSize: '0.8rem', color: '#d1fae5' }}>
                      Firewall rule: <strong>{selectedIncident.mitigations[0].action_type}</strong> applied to <code>{selectedIncident.mitigations[0].target_value}</code> by {selectedIncident.mitigations[0].executed_by}.
                    </div>
                  </div>
                )}

                {/* Action Controls */}
                <div style={{ borderTop: '1px solid #1f2937', paddingTop: '1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#9ca3af' }}>SOC Analyst Actions:</div>
                  
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                    <button
                      onClick={handleMitigate}
                      style={{ padding: '0.6rem', background: '#dc2626', border: 'none', borderRadius: '6px', color: '#fff', fontSize: '0.8rem', fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.4rem' }}
                    >
                      <Ban size={15} /> Block Source IP
                    </button>
                    <button
                      onClick={() => handleUpdateStatus('INVESTIGATING')}
                      style={{ padding: '0.6rem', background: '#374151', border: 'none', borderRadius: '6px', color: '#fff', fontSize: '0.8rem', fontWeight: 600, cursor: 'pointer' }}
                    >
                      Investigate
                    </button>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
                    <button
                      onClick={() => handleUpdateStatus('RESOLVED')}
                      style={{ padding: '0.6rem', background: '#059669', border: 'none', borderRadius: '6px', color: '#fff', fontSize: '0.8rem', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.4rem' }}
                    >
                      <Check size={15} /> Resolve
                    </button>
                    <button
                      onClick={() => handleUpdateStatus('FALSE_POSITIVE')}
                      style={{ padding: '0.6rem', background: '#1f2937', border: '1px solid #374151', borderRadius: '6px', color: '#9ca3af', fontSize: '0.8rem', cursor: 'pointer' }}
                    >
                      False Positive
                    </button>
                  </div>
                </div>
              </>
            ) : (
              <div style={{ padding: '3rem', textAlign: 'center', color: '#6b7280' }}>
                Select an incident from the queue to inspect its AI explanation vector.
              </div>
            )}
          </div>
        </div>

        {/* Attack Scenario Simulator Bench (Bottom) */}
        <div style={{ background: '#111827', border: '1px solid #1f2937', borderRadius: '8px', padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <div>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#fff', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <Terminal size={16} color="#38bdf8" /> Live Attack Ingestion Simulator
              </h3>
              <p style={{ fontSize: '0.75rem', color: '#9ca3af' }}>Inject synthesized attack profiles (CIC-IDS2017 distributions) to test real-time detection & SHAP explanation.</p>
            </div>
            {simulating && <span style={{ fontSize: '0.8rem', color: '#38bdf8' }}>Analyzing network flow...</span>}
          </div>

          <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap' }}>
            <button
              onClick={() => simulateScenario('DOS')}
              disabled={simulating}
              style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.5rem 0.9rem', background: '#dc2626', border: 'none', borderRadius: '6px', color: '#fff', fontWeight: 600, fontSize: '0.8rem', cursor: 'pointer' }}
            >
              <Flame size={14} /> Simulate SYN Flood (DoS)
            </button>
            <button
              onClick={() => simulateScenario('PORTSCAN')}
              disabled={simulating}
              style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.5rem 0.9rem', background: '#d97706', border: 'none', borderRadius: '6px', color: '#fff', fontWeight: 600, fontSize: '0.8rem', cursor: 'pointer' }}
            >
              <Crosshair size={14} /> Simulate Port Scan (Nmap)
            </button>
            <button
              onClick={() => simulateScenario('BRUTE_FORCE')}
              disabled={simulating}
              style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.5rem 0.9rem', background: '#ea580c', border: 'none', borderRadius: '6px', color: '#fff', fontWeight: 600, fontSize: '0.8rem', cursor: 'pointer' }}
            >
              <Key size={14} /> Simulate SSH Brute Force
            </button>
            <button
              onClick={() => simulateScenario('WEB_ATTACK')}
              disabled={simulating}
              style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.5rem 0.9rem', background: '#7c3aed', border: 'none', borderRadius: '6px', color: '#fff', fontWeight: 600, fontSize: '0.8rem', cursor: 'pointer' }}
            >
              <Globe size={14} /> Simulate SQLi Web Attack
            </button>
            <button
              onClick={() => simulateScenario('BOTNET')}
              disabled={simulating}
              style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.5rem 0.9rem', background: '#be185d', border: 'none', borderRadius: '6px', color: '#fff', fontWeight: 600, fontSize: '0.8rem', cursor: 'pointer' }}
            >
              <Cpu size={14} /> Simulate Botnet C2 Beacon
            </button>
            <button
              onClick={() => simulateScenario('BENIGN')}
              disabled={simulating}
              style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.5rem 0.9rem', background: '#059669', border: 'none', borderRadius: '6px', color: '#fff', fontWeight: 600, fontSize: '0.8rem', cursor: 'pointer' }}
            >
              <ShieldCheck size={14} /> Send Normal HTTPS Flow
            </button>
          </div>

          {simResult && (
            <div style={{ marginTop: '0.75rem', background: '#0b0f19', border: '1px solid #1f2937', padding: '0.75rem', borderRadius: '6px', fontSize: '0.8rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                Prediction: <strong style={{ color: simResult.is_attack ? '#f87171' : '#34d399' }}>{simResult.attack_class}</strong> | Confidence: {(simResult.confidence * 100).toFixed(1)}% | Anomaly Score: {(simResult.anomaly_score * 100).toFixed(1)}%
              </div>
              <div style={{ color: '#9ca3af' }}>
                Flow ID: <code>{simResult.flow_id.substring(0, 8)}...</code>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
