export interface User {
  id: string;
  email: string;
  full_name: string;
  role: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user_id: string;
  email: string;
  full_name: string;
  role: string;
}

export interface ThreatStats {
  total_flows: number;
  total_threats: number;
  active_incidents: number;
  mitigated_incidents: number;
  threat_level: 'LOW' | 'ELEVATED' | 'HIGH' | 'SEVERE';
  attack_vector_breakdown: Record<string, number>;
}

export interface ShapContribution {
  feature: string;
  value: number;
  shap_value: number;
  impact: 'INCREASES_RISK' | 'DECREASES_RISK';
  abs_impact: number;
}

export interface ShapExplanation {
  predicted_class: string;
  summary: string;
  top_features: ShapContribution[];
  all_features: Record<string, number>;
}

export interface Alert {
  id: string;
  attack_class: string;
  confidence: number;
  shap_values?: ShapExplanation;
  created_at: string;
}

export interface Mitigation {
  id: string;
  action_type: string;
  target_value: string;
  executed_by: string;
  status: string;
  executed_at: string;
}

export interface Incident {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'DETECTED' | 'AUTO_MITIGATED' | 'INVESTIGATING' | 'MITIGATED' | 'RESOLVED' | 'FALSE_POSITIVE';
  primary_attack_vector: string;
  risk_score: number;
  src_ip: string;
  dst_ip: string;
  assigned_to?: string;
  created_at: string;
  updated_at: string;
  alerts?: Alert[];
  mitigations?: Mitigation[];
}

export interface FlowIngestResult {
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  attack_class: string;
  confidence: number;
  is_attack: boolean;
  is_anomaly: boolean;
  anomaly_score: number;
  incident_id?: string;
  shap_explanation?: ShapExplanation;
}
