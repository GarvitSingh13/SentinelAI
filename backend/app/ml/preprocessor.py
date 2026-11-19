import numpy as np
from typing import Dict, Any, List

FEATURE_NAMES = [
    "flow_duration_ms",
    "total_fwd_packets",
    "total_bwd_packets",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "flow_iat_mean",
    "flow_iat_std",
    "fwd_packet_length_mean",
    "bwd_packet_length_mean",
    "packet_length_std",
    "syn_flag_count",
    "fin_flag_count",
    "rst_flag_count",
    "psh_flag_count",
    "ack_flag_count",
    "down_up_ratio",
    "dst_port",
    "protocol_num"
]

CLASS_NAMES = [
    "BENIGN",
    "DOS_DDOS",
    "PORTSCAN",
    "BRUTE_FORCE",
    "WEB_ATTACK",
    "BOTNET"
]

PROTOCOL_MAP = {
    "TCP": 6,
    "UDP": 17,
    "ICMP": 1,
    "OTHER": 0
}

def extract_features(flow: Dict[str, Any]) -> np.ndarray:
    """Extract and order features from raw flow dictionary matching CIC-IDS2017 schema."""
    proto_str = str(flow.get("protocol", "TCP")).upper()
    proto_num = PROTOCOL_MAP.get(proto_str, 6)

    total_fwd = float(flow.get("total_fwd_packets", 1))
    total_bwd = float(flow.get("total_bwd_packets", 0))
    down_up_ratio = total_bwd / max(1.0, total_fwd)

    row = [
        float(flow.get("flow_duration_ms", 100.0)),
        total_fwd,
        total_bwd,
        float(flow.get("flow_bytes_per_sec", 1000.0)),
        float(flow.get("flow_packets_per_sec", 10.0)),
        float(flow.get("flow_iat_mean", 50.0)),
        float(flow.get("flow_iat_std", 15.0)),
        float(flow.get("fwd_packet_length_mean", 250.0)),
        float(flow.get("bwd_packet_length_mean", 350.0)),
        float(flow.get("packet_length_std", 40.0)),
        float(flow.get("syn_flag_count", 0)),
        float(flow.get("fin_flag_count", 0)),
        float(flow.get("rst_flag_count", 0)),
        float(flow.get("psh_flag_count", 0)),
        float(flow.get("ack_flag_count", 1)),
        down_up_ratio,
        float(flow.get("dst_port", 80)),
        float(proto_num)
    ]
    return np.array(row, dtype=np.float32)

def extract_batch(flows: List[Dict[str, Any]]) -> np.ndarray:
    return np.vstack([extract_features(f) for f in flows])
