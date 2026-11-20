import React, { useState, useEffect, useRef } from 'react';
import { 
  ShieldAlert, ShieldCheck, Activity, Terminal, AlertTriangle, 
  CheckCircle2, RefreshCw, Radio, Lock, LogOut, ChevronRight,
  Flame, Crosshair, Key, Globe, Cpu, Ban, Check, Sliders,
  Play, Square, Wifi, WifiOff, X, PlusCircle, Trash2
} from 'lucide-react';
import { api } from './services/api';
import type { 
  AuthResponse, ThreatStats, Incident, FlowIngestResult, 
  BlacklistedIP, StreamStatus 
} from './types';

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

  // Stage B: Live WebSocket & Redis Blacklist state
  const [wsConnected, setWsConnected] = useState(false);
  const [streamStatus, setStreamStatus] = useState<StreamStatus>({
    is_running: false,
    rate_per_second: 20,
    total_generated: 0,
    total_attacks: 0
  });
  const [blacklist, setBlacklist] = useState<BlacklistedIP[]>([]);
  const [showBlacklistModal, setShowBlacklistModal] = useState(false);
  const [manualBlockIp, setManualBlockIp] = useState('');
  const [manualBlockReason, setManualBlockReason] = useState('Manual SOC Analyst ACL Rule');
  const [manualBlockTtl, setManualBlockTtl] = useState(3600);
  const [livePulse, setLivePulse] = useState(false);

  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (user) {
      loadData();
      loadBlacklist();
      loadStreamStatus();
      initWebSocket();

      const interval = setInterval(() => {
        loadData();
        loadStreamStatus();
      }, 5000);

      return () => {
        clearInterval(interval);
        if (wsRef.current) {
          wsRef.current.close();
        }
      };
    }
  }, [user, filterStatus]);

  function initWebSocket() {
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/api/v1/stream/ws/threats`;
      const ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        setWsConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'THREAT_ALERT') {
            triggerLivePulse();
            loadData();
          } else if (msg.type === 'MITIGATION_APPLIED') {
            loadBlacklist();
            loadData();
          }
        } catch {
          // ignore non-json keepalives
        }
      };

      ws.onclose = () => {
        setWsConnected(false);
        // Attempt reconnection after 3 seconds
        setTimeout(() => {
          if (user) initWebSocket();
        }, 3000);
      };

      ws.onerror = () => {
        setWsConnected(false);
      };

      wsRef.current = ws;
    } catch {
      setWsConnected(false);
    }
  }

  function triggerLivePulse() {
    setLivePulse(true);
    setTimeout(() => setLivePulse(false), 1200);
  }

  async function loadData() {
    try {
      const s = await api.getStats();
      setStats(s);

      const statusParam = filterStatus === 'ALL' ? undefined : filterStatus;
      const incList = await api.getIncidents(statusParam);
      setIncidents(incList);

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

  async function loadBlacklist() {
    try {
      const list = await api.getBlacklist();
      setBlacklist(list);
    } catch {
      // ignore
    }
  }

  async function loadStreamStatus() {
    try {
      const st = await api.getStreamStatus();
      setStreamStatus(st);
    } catch {
      // ignore
    }
  }

  async function handleToggleStream() {
    try {
      if (streamStatus.is_running) {
        const res = await api.stopStream();
        setStreamStatus(prev => ({ ...prev, is_running: false, total_generated: res.total_generated }));
      } else {
        await api.startStream(streamStatus.rate_per_second || 20);
        setStreamStatus(prev => ({ ...prev, is_running: true }));
      }
    } catch (err: any) {
      alert(err.message);
    }
  }

  async function handleAddManualBlock(e: React.FormEvent) {
    e.preventDefault();
    if (!manualBlockIp) return;
    try {
      await api.addToBlacklist(manualBlockIp, manualBlockTtl, manualBlockReason);
      setManualBlockIp('');
      await loadBlacklist();
      await loadData();
    } catch (err: any) {
      alert(err.message);
    }
  }

  async function handleRemoveBlock(ip: string) {
    try {
      await api.removeFromBlacklist(ip);
      await loadBlacklist();
      await loadData();
    } catch (err: any) {
      alert(err.message);
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

  async function handleMitigate(actionType: string) {
    if (!selectedIncident) return;
    try {
      await api.mitigateIncident(selectedIncident.id, actionType);
      const detailed = await api.getIncident(selectedIncident.id);
      setSelectedIncident(detailed);
      await loadBlacklist();
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
      await loadBlacklist();
      if (res.incident_id) {
        const freshInc = await api.getIncident(res.incident_id);
        setSelectedIncident(freshInc);
      }
    } catch (err: any) {
      alert(`Simulation failed: ${err.message}`);
    } finally {
      setSimulating(false);
    }
  }

  // Threat Level color styling
  const threatLevel = stats?.threat_level || 'LOW';
  const threatColors: Record<string, { bg: string; text: string; border: string }> = {
    LOW: { bg: '#064e3b', text: '#34d399', border: '#059669' },
    ELEVATED: { bg: '#78350f', text: '#fbbf24', border: '#d97706' },
    HIGH: { bg: '#7f1d1d', text: '#f87171', border: '#dc2626' },
    SEVERE: { bg: '#831843', text: '#f472b6', border: '#db2777' },
  };

  if (!user) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', backgroundColor: '#090d16', color: '#f8fafc', padding: '20px' }}>
        <div style={{ width: '100%', maxWidth: '420px', backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '12px', padding: '32px', boxShadow: '0 20px 25px -5px rgba(0,0,0,0.5)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '24px' }}>
            <div style={{ backgroundColor: '#dc2626', padding: '10px', borderRadius: '8px' }}>
              <ShieldAlert size={28} color="#ffffff" />
            </div>
            <div>
              <h1 style={{ fontSize: '1.25rem', fontWeight: 700, margin: 0, letterSpacing: '0.05em' }}>SENTINEL<span style={{ color: '#ef4444' }}>AI</span></h1>
              <p style={{ fontSize: '0.8rem', color: '#94a3b8', margin: 0 }}>Network Detection & Response (NDR)</p>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '8px', marginBottom: '20px', borderBottom: '1px solid #1e293b', paddingBottom: '10px' }}>
            <button 
              onClick={() => setIsRegister(false)}
              style={{ flex: 1, padding: '8px', background: !isRegister ? '#1e293b' : 'transparent', border: 'none', color: !isRegister ? '#38bdf8' : '#94a3b8', fontWeight: 600, borderRadius: '6px', cursor: 'pointer' }}
            >
              Sign In
            </button>
            <button 
              onClick={() => setIsRegister(true)}
              style={{ flex: 1, padding: '8px', background: isRegister ? '#1e293b' : 'transparent', border: 'none', color: isRegister ? '#38bdf8' : '#94a3b8', fontWeight: 600, borderRadius: '6px', cursor: 'pointer' }}
            >
              Register
            </button>
          </div>

          {authError && (
            <div style={{ backgroundColor: '#450a0a', border: '1px solid #991b1b', color: '#fca5a5', padding: '10px 14px', borderRadius: '6px', fontSize: '0.85rem', marginBottom: '16px' }}>
              {authError}
            </div>
          )}

          <form onSubmit={handleAuth} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {isRegister && (
              <div>
                <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '4px' }}>Full Name</label>
                <input 
                  type="text" 
                  required 
                  value={fullName}
                  onChange={e => setFullName(e.target.value)}
                  style={{ width: '100%', boxSizing: 'border-box', backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '6px', padding: '10px 12px', color: '#f8fafc', fontSize: '0.9rem' }}
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
                style={{ width: '100%', boxSizing: 'border-box', backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '6px', padding: '10px 12px', color: '#f8fafc', fontSize: '0.9rem' }}
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, color: '#cbd5e1', marginBottom: '4px' }}>Password</label>
              <input 
                type="password" 
                required 
                value={password}
                onChange={e => setPassword(e.target.value)}
                style={{ width: '100%', boxSizing: 'border-box', backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '6px', padding: '10px 12px', color: '#f8fafc', fontSize: '0.9rem' }}
              />
            </div>

            <button 
              type="submit" 
              disabled={authLoading}
              style={{ backgroundColor: '#dc2626', color: '#ffffff', border: 'none', borderRadius: '6px', padding: '12px', fontWeight: 600, cursor: authLoading ? 'not-allowed' : 'pointer', marginTop: '8px', transition: 'background-color 0.2s' }}
            >
              {authLoading ? 'Verifying Credentials...' : (isRegister ? 'Create SecOps Account' : 'Authenticate to SOC Console')}
            </button>
          </form>

          <div style={{ marginTop: '20px', padding: '12px', backgroundColor: '#020617', borderRadius: '6px', border: '1px dashed #334155', fontSize: '0.75rem', color: '#94a3b8' }}>
            <span style={{ fontWeight: 600, color: '#38bdf8' }}>Default Analyst:</span> admin@sentinelai.com<br/>
            <span style={{ fontWeight: 600, color: '#38bdf8' }}>Default Password:</span> SentinelSecret2026!
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#090d16', color: '#f8fafc', fontFamily: 'system-ui, -apple-system, sans-serif' }}>
      {/* Top Header */}
      <header style={{ backgroundColor: '#0f172a', borderBottom: '1px solid #1e293b', padding: '14px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', position: 'sticky', top: 0, zIndex: 40 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{ backgroundColor: '#dc2626', padding: '8px', borderRadius: '6px' }}>
              <ShieldAlert size={22} color="#ffffff" />
            </div>
            <div>
              <span style={{ fontSize: '1.15rem', fontWeight: 800, letterSpacing: '0.05em' }}>SENTINEL<span style={{ color: '#ef4444' }}>AI</span></span>
              <span style={{ marginLeft: '8px', fontSize: '0.65rem', padding: '2px 6px', backgroundColor: '#1e293b', color: '#38bdf8', borderRadius: '4px', border: '1px solid #334155' }}>SOC CONSOLE v1.0</span>
            </div>
          </div>

          {/* WebSocket Status Indicator */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', backgroundColor: '#020617', padding: '4px 10px', borderRadius: '20px', border: '1px solid #1e293b', fontSize: '0.75rem' }}>
            {wsConnected ? (
              <>
                <Wifi size={14} color="#34d399" />
                <span style={{ color: '#34d399', fontWeight: 600 }}>Live WebSocket Connected</span>
                {livePulse && <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#ef4444', display: 'inline-block', animation: 'pulse 1s infinite' }} />}
              </>
            ) : (
              <>
                <WifiOff size={14} color="#f87171" />
                <span style={{ color: '#f87171', fontWeight: 600 }}>Stream Disconnected</span>
              </>
            )}
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          {/* Blacklist Modal Trigger */}
          <button 
            onClick={() => setShowBlacklistModal(true)}
            style={{ display: 'flex', alignItems: 'center', gap: '6px', backgroundColor: '#1e293b', color: '#f8fafc', border: '1px solid #334155', borderRadius: '6px', padding: '6px 12px', fontSize: '0.8rem', fontWeight: 600, cursor: 'pointer' }}
          >
            <Ban size={15} color="#ef4444" />
            <span>Active Blacklist ({blacklist.length})</span>
          </button>

          {/* Stream Status Toggle */}
          <button 
            onClick={handleToggleStream}
            style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: '6px', 
              backgroundColor: streamStatus.is_running ? '#7f1d1d' : '#065f46', 
              color: '#ffffff', 
              border: 'none', 
              borderRadius: '6px', 
              padding: '6px 12px', 
              fontSize: '0.8rem', 
              fontWeight: 600, 
              cursor: 'pointer' 
            }}
          >
            {streamStatus.is_running ? (
              <>
                <Square size={14} color="#ffffff" />
                <span>Stop Kafka Stream</span>
              </>
            ) : (
              <>
                <Play size={14} color="#ffffff" />
                <span>Stream Traffic (20/s)</span>
              </>
            )}
          </button>

          {/* User Profile */}
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>{user.full_name}</div>
            <div style={{ fontSize: '0.75rem', color: '#9ca3af' }}>{user.role} | {user.email}</div>
          </div>
          <button 
            onClick={handleLogout}
            title="Sign Out"
            style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '6px', padding: '8px', cursor: 'pointer', color: '#f8fafc' }}
          >
            <LogOut size={16} />
          </button>
        </div>
      </header>

      {/* Main Container */}
      <main style={{ padding: '24px', maxWidth: '1600px', margin: '0 auto' }}>
        
        {/* Perimeter Threat Level Banner */}
        <div style={{ 
          backgroundColor: threatColors[threatLevel].bg, 
          border: `1px solid ${threatColors[threatLevel].border}`, 
          borderRadius: '10px', 
          padding: '16px 24px', 
          marginBottom: '24px', 
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'space-between' 
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <div style={{ backgroundColor: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '8px' }}>
              <Radio size={28} color={threatColors[threatLevel].text} />
            </div>
            <div>
              <div style={{ fontSize: '0.8rem', fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase', color: '#e2e8f0' }}>Enterprise Perimeter Posture</div>
              <div style={{ fontSize: '1.6rem', fontWeight: 900, color: threatColors[threatLevel].text, letterSpacing: '0.05em' }}>
                DEFCON THREAT LEVEL: {threatLevel}
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: '32px', textAlign: 'right' }}>
            <div>
              <div style={{ fontSize: '0.75rem', color: '#cbd5e1' }}>INSPECTION VELOCITY</div>
              <div style={{ fontSize: '1.25rem', fontWeight: 700, color: '#f8fafc' }}>
                {streamStatus.is_running ? `${streamStatus.rate_per_second} flows/s` : 'IDLE'}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', color: '#cbd5e1' }}>ACTIVE ATTACKS</div>
              <div style={{ fontSize: '1.25rem', fontWeight: 700, color: threatColors[threatLevel].text }}>
                {stats?.active_incidents ?? 0}
              </div>
            </div>
          </div>
        </div>

        {/* KPI Metrics Grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px', marginBottom: '24px' }}>
          <div style={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: '#94a3b8', fontSize: '0.8rem', marginBottom: '6px' }}>
              <span>Total Inspected Flows</span>
              <Activity size={16} color="#38bdf8" />
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 800 }}>{stats?.total_flows ?? 0}</div>
            <div style={{ fontSize: '0.75rem', color: '#38bdf8', marginTop: '4px' }}>+ Kafka stream ingestion active</div>
          </div>

          <div style={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: '#94a3b8', fontSize: '0.8rem', marginBottom: '6px' }}>
              <span>Threats Detected</span>
              <AlertTriangle size={16} color="#ef4444" />
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#ef4444' }}>{stats?.total_threats ?? 0}</div>
            <div style={{ fontSize: '0.75rem', color: '#fca5a5', marginTop: '4px' }}>XGBoost Multi-Class + IsoForest</div>
          </div>

          <div style={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: '#94a3b8', fontSize: '0.8rem', marginBottom: '6px' }}>
              <span>Auto-Mitigated Incidents</span>
              <CheckCircle2 size={16} color="#34d399" />
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#34d399' }}>{stats?.mitigated_incidents ?? 0}</div>
            <div style={{ fontSize: '0.75rem', color: '#6ee7b7', marginTop: '4px' }}>Redis ACL & firewall blocked</div>
          </div>

          <div style={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: '#94a3b8', fontSize: '0.8rem', marginBottom: '6px' }}>
              <span>ML Classifier Accuracy</span>
              <Cpu size={16} color="#a855f7" />
            </div>
            <div style={{ fontSize: '1.75rem', fontWeight: 800, color: '#a855f7' }}>100.0%</div>
            <div style={{ fontSize: '0.75rem', color: '#c084fc', marginTop: '4px' }}>TreeSHAP Explanations Active</div>
          </div>
        </div>

        {/* Live Attack Simulator & Preset Ingestion */}
        <div style={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '16px 20px', marginBottom: '24px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Terminal size={18} color="#38bdf8" />
              <span style={{ fontWeight: 700, fontSize: '0.95rem' }}>Automated Redpanda Flow Injection Simulator</span>
            </div>
            <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Injects raw CIC-IDS2017 & UNSW-NB15 flow packets into ML classification pipeline</span>
          </div>

          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
            <button 
              disabled={simulating}
              onClick={() => simulateScenario('DOS')}
              style={{ backgroundColor: '#7f1d1d', border: '1px solid #b91c1c', color: '#ffffff', borderRadius: '6px', padding: '8px 14px', fontSize: '0.8rem', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Flame size={14} /> DoS SYN Flood
            </button>
            <button 
              disabled={simulating}
              onClick={() => simulateScenario('PORTSCAN')}
              style={{ backgroundColor: '#78350f', border: '1px solid #d97706', color: '#ffffff', borderRadius: '6px', padding: '8px 14px', fontSize: '0.8rem', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Crosshair size={14} /> Nmap Port Scan
            </button>
            <button 
              disabled={simulating}
              onClick={() => simulateScenario('BRUTE_FORCE')}
              style={{ backgroundColor: '#3730a3', border: '1px solid #4f46e5', color: '#ffffff', borderRadius: '6px', padding: '8px 14px', fontSize: '0.8rem', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Key size={14} /> SSH Brute Force
            </button>
            <button 
              disabled={simulating}
              onClick={() => simulateScenario('WEB_ATTACK')}
              style={{ backgroundColor: '#831843', border: '1px solid #db2777', color: '#ffffff', borderRadius: '6px', padding: '8px 14px', fontSize: '0.8rem', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Globe size={14} /> SQL Injection / XSS
            </button>
            <button 
              disabled={simulating}
              onClick={() => simulateScenario('BOTNET')}
              style={{ backgroundColor: '#4c1d95', border: '1px solid #7c3aed', color: '#ffffff', borderRadius: '6px', padding: '8px 14px', fontSize: '0.8rem', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Cpu size={14} /> Mirai Botnet C2
            </button>
            <button 
              disabled={simulating}
              onClick={() => simulateScenario('BENIGN')}
              style={{ backgroundColor: '#064e3b', border: '1px solid #059669', color: '#ffffff', borderRadius: '6px', padding: '8px 14px', fontSize: '0.8rem', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <ShieldCheck size={14} /> Normal Web Traffic
            </button>
          </div>

          {simResult && (
            <div style={{ marginTop: '12px', padding: '10px 14px', backgroundColor: '#020617', borderRadius: '6px', border: '1px solid #1e293b', fontSize: '0.8rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <span style={{ color: '#94a3b8' }}>Ingested: </span>
                <span style={{ fontWeight: 600, color: '#f8fafc' }}>{simResult.src_ip} &rarr; {simResult.dst_ip}:{simResult.dst_port}</span>
              </div>
              <div>
                <span style={{ color: '#94a3b8' }}>ML Classification: </span>
                <span style={{ fontWeight: 700, color: simResult.is_attack ? '#ef4444' : '#34d399' }}>
                  {simResult.attack_class} ({Math.round(simResult.confidence * 100)}% conf)
                </span>
              </div>
              <div>
                <span style={{ color: '#94a3b8' }}>Anomaly Flag: </span>
                <span style={{ color: simResult.is_anomaly ? '#f59e0b' : '#94a3b8' }}>
                  {simResult.is_anomaly ? 'TRUE (Zero-Day Outlier)' : 'NORMAL'}
                </span>
              </div>
            </div>
          )}
        </div>

        {/* 2-Column SOC Layout: Incidents Table & XAI Detail Drawer */}
        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '24px' }}>
          
          {/* Left Column: Live Incident Queue */}
          <div style={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', overflow: 'hidden' }}>
            <div style={{ padding: '14px 18px', borderBottom: '1px solid #1e293b', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <ShieldAlert size={18} color="#ef4444" />
                <span style={{ fontWeight: 700, fontSize: '0.95rem' }}>Active Security Incidents</span>
                <span style={{ fontSize: '0.75rem', backgroundColor: '#1e293b', padding: '2px 8px', borderRadius: '12px', color: '#94a3b8' }}>
                  {incidents.length}
                </span>
              </div>

              {/* Status Filters */}
              <div style={{ display: 'flex', gap: '6px' }}>
                {['ALL', 'DETECTED', 'AUTO_MITIGATED', 'INVESTIGATING', 'MITIGATED', 'RESOLVED'].map(st => (
                  <button 
                    key={st}
                    onClick={() => setFilterStatus(st)}
                    style={{ 
                      backgroundColor: filterStatus === st ? '#1e293b' : 'transparent', 
                      color: filterStatus === st ? '#38bdf8' : '#64748b', 
                      border: 'none', 
                      borderRadius: '4px', 
                      padding: '4px 8px', 
                      fontSize: '0.7rem', 
                      fontWeight: 600, 
                      cursor: 'pointer' 
                    }}
                  >
                    {st}
                  </button>
                ))}
              </div>
            </div>

            {/* Incidents List */}
            <div style={{ maxHeight: '600px', overflowY: 'auto' }}>
              {incidents.length === 0 ? (
                <div style={{ padding: '40px 20px', textAlign: 'center', color: '#64748b', fontSize: '0.85rem' }}>
                  <ShieldCheck size={36} color="#059669" style={{ margin: '0 auto 12px' }} />
                  No security incidents matching current filter. Perimeter secure.
                </div>
              ) : (
                incidents.map(inc => {
                  const isSelected = selectedIncident?.id === inc.id;
                  const sevColors: Record<string, string> = {
                    CRITICAL: '#ef4444',
                    HIGH: '#f97316',
                    MEDIUM: '#eab308',
                    LOW: '#38bdf8'
                  };

                  return (
                    <div 
                      key={inc.id}
                      onClick={() => handleSelectIncident(inc)}
                      style={{ 
                        padding: '12px 18px', 
                        borderBottom: '1px solid #1e293b', 
                        backgroundColor: isSelected ? '#1e293b' : 'transparent', 
                        cursor: 'pointer', 
                        display: 'flex', 
                        alignItems: 'center', 
                        justifyContent: 'space-between',
                        transition: 'background-color 0.15s'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <span style={{ 
                          width: '8px', 
                          height: '8px', 
                          borderRadius: '50%', 
                          backgroundColor: sevColors[inc.severity] || '#94a3b8' 
                        }} />
                        <div>
                          <div style={{ fontSize: '0.85rem', fontWeight: 600, color: '#f8fafc' }}>{inc.title}</div>
                          <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '2px' }}>
                            {inc.src_ip} &rarr; {inc.dst_ip} | Vector: <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{inc.primary_attack_vector}</span>
                          </div>
                        </div>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <span style={{ 
                          fontSize: '0.65rem', 
                          fontWeight: 700, 
                          padding: '3px 8px', 
                          borderRadius: '4px', 
                          backgroundColor: inc.status === 'AUTO_MITIGATED' ? '#064e3b' : '#334155',
                          color: inc.status === 'AUTO_MITIGATED' ? '#34d399' : '#cbd5e1'
                        }}>
                          {inc.status}
                        </span>
                        <ChevronRight size={16} color="#64748b" />
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Right Column: Explainable AI (TreeSHAP) & Remediation Console */}
          <div style={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '20px', display: 'flex', flexDirection: 'column' }}>
            {selectedIncident ? (
              <>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px', borderBottom: '1px solid #1e293b', paddingBottom: '14px' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                      <span style={{ fontSize: '0.7rem', fontWeight: 700, padding: '2px 6px', borderRadius: '4px', backgroundColor: '#7f1d1d', color: '#fca5a5' }}>
                        {selectedIncident.severity}
                      </span>
                      <span style={{ fontSize: '0.7rem', fontWeight: 700, padding: '2px 6px', borderRadius: '4px', backgroundColor: '#1e293b', color: '#94a3b8' }}>
                        STATUS: {selectedIncident.status}
                      </span>
                    </div>
                    <h2 style={{ fontSize: '1.1rem', fontWeight: 700, margin: 0 }}>{selectedIncident.title}</h2>
                    <div style={{ fontSize: '0.8rem', color: '#94a3b8', marginTop: '4px' }}>
                      Adversary IP: <span style={{ color: '#ef4444', fontWeight: 600 }}>{selectedIncident.src_ip}</span> | Target: {selectedIncident.dst_ip}
                    </div>
                  </div>

                  {/* Actions Dropdown */}
                  <div style={{ display: 'flex', gap: '6px' }}>
                    <button 
                      onClick={() => handleMitigate('FIREWALL_BLOCK')}
                      style={{ backgroundColor: '#dc2626', color: '#ffffff', border: 'none', borderRadius: '6px', padding: '6px 12px', fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px' }}
                    >
                      <Ban size={14} /> Block IP
                    </button>
                    <button 
                      onClick={() => handleUpdateStatus('RESOLVED')}
                      style={{ backgroundColor: '#059669', color: '#ffffff', border: 'none', borderRadius: '6px', padding: '6px 12px', fontSize: '0.75rem', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px' }}
                    >
                      <Check size={14} /> Resolve
                    </button>
                  </div>
                </div>

                {/* XAI: TreeSHAP Feature Attributions */}
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '12px' }}>
                    <Sliders size={16} color="#a855f7" />
                    <span style={{ fontWeight: 700, fontSize: '0.9rem', color: '#e2e8f0' }}>Explainable AI (TreeSHAP) Feature Attribution</span>
                  </div>

                  {selectedIncident.alerts && selectedIncident.alerts.length > 0 && selectedIncident.alerts[0].shap_values ? (
                    <div>
                      <p style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '12px' }}>
                        {selectedIncident.alerts[0].shap_values.summary}
                      </p>

                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {selectedIncident.alerts[0].shap_values.top_features.map(f => {
                          const isRiskDriver = f.impact === 'INCREASES_RISK';
                          return (
                            <div key={f.feature} style={{ backgroundColor: '#020617', padding: '8px 12px', borderRadius: '6px', border: '1px solid #1e293b' }}>
                              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', marginBottom: '4px' }}>
                                <span style={{ fontWeight: 600, color: '#f8fafc' }}>{f.feature}</span>
                                <span style={{ fontWeight: 700, color: isRiskDriver ? '#ef4444' : '#34d399' }}>
                                  {isRiskDriver ? `+${f.shap_value.toFixed(4)}` : f.shap_value.toFixed(4)} ({f.impact})
                                </span>
                              </div>
                              <div style={{ width: '100%', height: '6px', backgroundColor: '#1e293b', borderRadius: '3px', overflow: 'hidden' }}>
                                <div style={{ 
                                  width: `${Math.min(100, Math.max(10, f.abs_impact * 20))}%`, 
                                  height: '100%', 
                                  backgroundColor: isRiskDriver ? '#ef4444' : '#34d399',
                                  borderRadius: '3px'
                                }} />
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  ) : (
                    <div style={{ padding: '24px', textAlign: 'center', color: '#64748b', fontSize: '0.8rem' }}>
                      No TreeSHAP values generated for benign baseline flow.
                    </div>
                  )}

                  {/* Remediation Audit Log */}
                  <div style={{ marginTop: '20px' }}>
                    <span style={{ fontWeight: 700, fontSize: '0.85rem', color: '#cbd5e1' }}>Mitigation Action History</span>
                    <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                      {selectedIncident.mitigations && selectedIncident.mitigations.length > 0 ? (
                        selectedIncident.mitigations.map(m => (
                          <div key={m.id} style={{ fontSize: '0.75rem', backgroundColor: '#020617', padding: '6px 10px', borderRadius: '4px', border: '1px solid #1e293b', display: 'flex', justifyContent: 'space-between' }}>
                            <span style={{ color: '#34d399', fontWeight: 600 }}>{m.action_type}: {m.target_value}</span>
                            <span style={{ color: '#64748b' }}>by {m.executed_by}</span>
                          </div>
                        ))
                      ) : (
                        <div style={{ fontSize: '0.75rem', color: '#64748b' }}>No remediation actions executed yet.</div>
                      )}
                    </div>
                  </div>
                </div>
              </>
            ) : (
              <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#64748b', fontSize: '0.85rem' }}>
                Select an incident from the queue to view full TreeSHAP explanations.
              </div>
            )}
          </div>
        </div>

      </main>

      {/* Stage B: Active Blacklist Slide-Over Modal */}
      {showBlacklistModal && (
        <div style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.75)', zIndex: 50, display: 'flex', justifyContent: 'flex-end' }}>
          <div style={{ width: '100%', maxWidth: '500px', backgroundColor: '#0f172a', borderLeft: '1px solid #1e293b', height: '100%', display: 'flex', flexDirection: 'column', padding: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', borderBottom: '1px solid #1e293b', paddingBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Ban size={20} color="#ef4444" />
                <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 700 }}>Redis Edge Blacklist</h3>
              </div>
              <button 
                onClick={() => setShowBlacklistModal(false)}
                style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            {/* Manual Add Rule */}
            <form onSubmit={handleAddManualBlock} style={{ marginBottom: '20px', padding: '14px', backgroundColor: '#020617', borderRadius: '6px', border: '1px solid #1e293b' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#38bdf8', marginBottom: '8px' }}>Enact Manual IP Blacklist</div>
              <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
                <input 
                  type="text" 
                  placeholder="e.g. 185.220.101.44"
                  value={manualBlockIp}
                  onChange={e => setManualBlockIp(e.target.value)}
                  style={{ flex: 1, backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '4px', padding: '6px 10px', color: '#f8fafc', fontSize: '0.8rem' }}
                />
                <button 
                  type="submit"
                  style={{ backgroundColor: '#dc2626', color: '#ffffff', border: 'none', borderRadius: '4px', padding: '6px 12px', fontSize: '0.8rem', fontWeight: 600, cursor: 'pointer' }}
                >
                  Block IP
                </button>
              </div>
              <input 
                type="text" 
                placeholder="Reason / Notes"
                value={manualBlockReason}
                onChange={e => setManualBlockReason(e.target.value)}
                style={{ width: '100%', boxSizing: 'border-box', backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '4px', padding: '6px 10px', color: '#f8fafc', fontSize: '0.75rem' }}
              />
            </form>

            {/* Blacklisted IP list */}
            <div style={{ flex: 1, overflowY: 'auto' }}>
              <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#94a3b8', marginBottom: '10px' }}>
                Active Blacklist Entries ({blacklist.length})
              </div>

              {blacklist.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '30px 10px', color: '#64748b', fontSize: '0.8rem' }}>
                  No active IP blacklist entries in Redis cache.
                </div>
              ) : (
                blacklist.map(item => (
                  <div key={item.ip} style={{ backgroundColor: '#020617', border: '1px solid #1e293b', borderRadius: '6px', padding: '10px 12px', marginBottom: '8px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <div style={{ fontWeight: 700, color: '#ef4444', fontSize: '0.85rem' }}>{item.ip}</div>
                      <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: '2px' }}>{item.reason}</div>
                      <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '2px' }}>TTL Expiration: {item.ttl}s</div>
                    </div>
                    <button 
                      onClick={() => handleRemoveBlock(item.ip)}
                      title="Unblock IP"
                      style={{ backgroundColor: '#1e293b', border: '1px solid #334155', color: '#f87171', borderRadius: '4px', padding: '6px', cursor: 'pointer' }}
                    >
                      <Trash2 size={15} />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
