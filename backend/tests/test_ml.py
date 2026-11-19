import pytest
import numpy as np
from app.ml.preprocessor import extract_features, FEATURE_NAMES, CLASS_NAMES
from app.ml.classifier import IntrusionClassifier
from app.ml.explainer import FlowExplainer

def test_feature_extraction():
    flow = {
        "src_ip": "10.0.0.5",
        "dst_ip": "192.168.1.1",
        "dst_port": 80,
        "protocol": "TCP",
        "flow_duration_ms": 150.0,
        "total_fwd_packets": 5,
        "total_bwd_packets": 4,
        "flow_bytes_per_sec": 5000.0,
        "flow_packets_per_sec": 60.0,
        "syn_flag_count": 1,
        "ack_flag_count": 1
    }
    features = extract_features(flow)
    assert isinstance(features, np.ndarray)
    assert len(features) == len(FEATURE_NAMES)
    assert features[16] == 80.0  # dst_port
    assert features[17] == 6.0   # TCP protocol num

def test_classifier_benign_flow():
    classifier = IntrusionClassifier.get_instance()
    normal_flow = {
        "dst_port": 443,
        "protocol": "TCP",
        "flow_duration_ms": 200.0,
        "total_fwd_packets": 8,
        "total_bwd_packets": 10,
        "fwd_packet_length_mean": 350.0,
        "bwd_packet_length_mean": 800.0,
        "flow_bytes_per_sec": 12000.0,
        "flow_packets_per_sec": 45.0,
        "flow_iat_mean": 25.0,
        "flow_iat_std": 12.0,
        "syn_flag_count": 1,
        "ack_flag_count": 17
    }
    res = classifier.predict_flow(normal_flow)
    assert res.attack_class == "BENIGN"
    assert res.confidence > 0.50
    assert not res.is_attack

def test_classifier_dos_flow():
    classifier = IntrusionClassifier.get_instance()
    dos_flow = {
        "dst_port": 80,
        "protocol": "TCP",
        "flow_duration_ms": 15.0,
        "total_fwd_packets": 250,
        "total_bwd_packets": 0,
        "fwd_packet_length_mean": 64.0,
        "bwd_packet_length_mean": 0.0,
        "flow_bytes_per_sec": 850000.0,
        "flow_packets_per_sec": 12000.0,
        "syn_flag_count": 250,
        "ack_flag_count": 0
    }
    res = classifier.predict_flow(dos_flow)
    assert res.attack_class == "DOS_DDOS"
    assert res.confidence > 0.70
    assert res.is_attack

def test_explainer_generates_shap():
    classifier = IntrusionClassifier.get_instance()
    explainer = FlowExplainer.get_instance()
    dos_flow = {
        "dst_port": 80,
        "protocol": "TCP",
        "flow_duration_ms": 10.0,
        "total_fwd_packets": 300,
        "total_bwd_packets": 0,
        "fwd_packet_length_mean": 60.0,
        "flow_bytes_per_sec": 900000.0,
        "flow_packets_per_sec": 15000.0,
        "syn_flag_count": 300,
        "ack_flag_count": 0
    }
    pred = classifier.predict_flow(dos_flow)
    explanation = explainer.explain(pred.raw_features, pred.attack_class, top_k=5)
    
    assert explanation["predicted_class"] == "DOS_DDOS"
    assert len(explanation["top_features"]) <= 5
    assert "summary" in explanation
    # Check that syn_flag_count or packet rate is an identified risk driver
    top_feature_names = [f["feature"] for f in explanation["top_features"]]
    assert any(feat in top_feature_names for feat in ["syn_flag_count", "flow_packets_per_sec", "total_fwd_packets"])
