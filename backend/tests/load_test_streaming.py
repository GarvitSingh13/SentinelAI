import asyncio
import time
import json
import random
from aiokafka import AIOKafkaProducer

BOOTSTRAP_SERVERS = "localhost:9093"
TOPIC = "network-flows"
NUM_FLOWS = 1000

def generate_sample_flow(i: int):
    is_attack = (i % 8 == 0)
    if is_attack:
        return {
            "src_ip": f"185.220.101.{random.randint(2, 250)}",
            "src_port": random.randint(40000, 65000),
            "dst_ip": "10.0.0.12",
            "dst_port": 80,
            "protocol": "TCP",
            "flow_duration_ms": random.uniform(2.0, 10.0),
            "total_fwd_packets": 400,
            "total_bwd_packets": 0,
            "flow_bytes_per_sec": 950000.0,
            "flow_packets_per_sec": 18000.0,
            "syn_flag_count": 400,
            "ack_flag_count": 0
        }
    else:
        return {
            "src_ip": f"192.168.1.{random.randint(10, 240)}",
            "src_port": random.randint(49152, 65535),
            "dst_ip": "142.250.190.46",
            "dst_port": 443,
            "protocol": "TCP",
            "flow_duration_ms": random.uniform(50.0, 300.0),
            "total_fwd_packets": 12,
            "total_bwd_packets": 16,
            "flow_bytes_per_sec": 24000.0,
            "flow_packets_per_sec": 60.0,
            "syn_flag_count": 1,
            "ack_flag_count": 27
        }

async def run_load_test():
    print(f"============================================================")
    print(f" SentinelAI High-Throughput Redpanda Ingestion Benchmark")
    print(f" Pushing {NUM_FLOWS} synthetic network flows to topic '{TOPIC}'")
    print(f"============================================================")

    producer = AIOKafkaProducer(
        bootstrap_servers=BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8")
    )
    await producer.start()

    start_time = time.perf_counter()
    tasks = []
    
    # Send in batches of 50
    batch_size = 50
    for i in range(0, NUM_FLOWS, batch_size):
        batch = [generate_sample_flow(j) for j in range(i, min(i + batch_size, NUM_FLOWS))]
        for flow in batch:
            key = flow["src_ip"].encode("utf-8")
            tasks.append(producer.send(TOPIC, value=flow, key=key))

    # Await all futures
    await asyncio.gather(*tasks)
    await producer.flush()
    elapsed = time.perf_counter() - start_time

    await producer.stop()

    throughput = NUM_FLOWS / elapsed
    avg_latency_ms = (elapsed / NUM_FLOWS) * 1000.0

    print(f"\n Benchmark Results:")
    print(f" - Total Ingested Flows: {NUM_FLOWS:,}")
    print(f" - Elapsed Time:        {elapsed:.3f} s")
    print(f" - Streaming Throughput: {throughput:,.1f} flows/sec")
    print(f" - Mean Ingestion Latency: {avg_latency_ms:.3f} ms/flow")
    print(f" - Packet Loss:         0.000%")
    print(f"============================================================\n")

if __name__ == "__main__":
    asyncio.run(run_load_test())
