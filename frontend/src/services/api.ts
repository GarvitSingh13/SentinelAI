import type { AuthResponse, ThreatStats, Incident, FlowIngestResult } from '../types';

const API_BASE = '/api/v1';

function getAuthHeaders(): HeadersInit {
  const token = localStorage.getItem('sentinelai_token');
  return {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (res.status === 401) {
    localStorage.removeItem('sentinelai_token');
    localStorage.removeItem('sentinelai_user');
    window.dispatchEvent(new Event('auth-change'));
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    const errorText = await res.text();
    let msg = errorText;
    try {
      const parsed = JSON.parse(errorText);
      msg = parsed.detail || parsed.message || errorText;
    } catch {}
    throw new Error(msg || `Request failed with status ${res.status}`);
  }
  return res.json();
}

export const api = {
  // Auth
  async login(email: string, password: string): Promise<AuthResponse> {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    return handleResponse<AuthResponse>(res);
  },

  async register(data: { email: string; password: string; full_name: string; role?: string }): Promise<AuthResponse> {
    const res = await fetch(`${API_BASE}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    return handleResponse<AuthResponse>(res);
  },

  // Stats
  async getStats(): Promise<ThreatStats> {
    const res = await fetch(`${API_BASE}/stats`, {
      headers: getAuthHeaders(),
    });
    return handleResponse<ThreatStats>(res);
  },

  // Incidents
  async getIncidents(status?: string, severity?: string): Promise<Incident[]> {
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (severity) params.append('severity', severity);
    const query = params.toString() ? `?${params.toString()}` : '';

    const res = await fetch(`${API_BASE}/incidents${query}`, {
      headers: getAuthHeaders(),
    });
    return handleResponse<Incident[]>(res);
  },

  async getIncident(id: string): Promise<Incident> {
    const res = await fetch(`${API_BASE}/incidents/${id}`, {
      headers: getAuthHeaders(),
    });
    return handleResponse<Incident>(res);
  },

  async updateIncidentStatus(id: string, status: string): Promise<Incident> {
    const res = await fetch(`${API_BASE}/incidents/${id}/status`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify({ status }),
    });
    return handleResponse<Incident>(res);
  },

  async mitigateIncident(id: string, actionType = 'BLOCK_IP'): Promise<any> {
    const res = await fetch(`${API_BASE}/incidents/${id}/mitigate`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ action_type: actionType }),
    });
    return handleResponse<any>(res);
  },

  // Flow Ingestion
  async ingestFlow(flowData: Record<string, any>): Promise<FlowIngestResult> {
    const res = await fetch(`${API_BASE}/flows/ingest`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(flowData),
    });
    return handleResponse<FlowIngestResult>(res);
  },
};
