import asyncio
import random
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from app.services.stream_producer import stream_producer

logger = logging.getLogger("sentinel.generator")

class TrafficGenerator:
    """Simulates realistic enterprise perimeter traffic with mixed benign traffic and attack bursts."""

    def __init__(self):
        self.is_running = False
        self._task: Optional[asyncio.Task] = None
        self.rate_per_second = 20
        self.total_generated = 0
        self.total_attacks = 0

    async def start(self, rate_per_second: int = 20):
        if self.is_running:
            return
        self.rate_per_second = max(1, min(rate_per_second, 500))
        self.is_running = True
        self._task = asyncio.create_task(self._generator_loop())
        logger.info("✓ TrafficGenerator started at %d flows/sec", self.rate_per_second)

    async def stop(self):
        if not self.is_running:
            return
        self.is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("TrafficGenerator stopped. Generated %d total flows.", self.total_generated)

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_running": self.is_running,
            "rate_per_second": self.rate_per_second,
            "total_generated": self.total_generated,
            "total_attacks": self.total_attacks
        }

    async def _generator_loop(self):
        while self.is_running:
            batch_size = max(1, self.rate_per_second // 4)
            delay = 0.25

            flows = [self._generate_random_flow() for _ in range(batch_size)]
            self.total_generated += len(flows)

            try:
                await stream_producer.send_batch(flows)
            except Exception as e:
                logger.error("Failed to stream flows: %s", str(e))

            await asyncio.sleep(delay)

    def _generate_random_flow(self) -> Dict[str, Any]:
        dice = random.random()

        if dice < 0.82:
            return self._generate_benign()
        elif dice < 0.88:
            self.total_attacks += 1
            return self._generate_dos()
        elif dice < 0.93:
            self.total_attacks += 1
            return self._generate_portscan()
        elif dice < 0.96:
            self.total_attacks += 1
            return self._generate_bruteforce()
        elif dice < 0.98:
            self.total_attacks += 1
            return self._generate_web_attack()
        else:
            self.total_attacks += 1
            return self._generate_botnet()

    def _generate_benign(self) -> Dict[str, Any]:
        src_ip = f"192.168.1.{random.randint(10, 220)}"
        external_ips = ["142.250.190.46", "104.244.42.1", "151.101.65.140", "172.217.16.206"]
        dst_ip = random.choice(external_ips)
        dst_port = random.choice([443, 80, 53, 8080])

        total_fwd = random.randint(5, 40)
        total_bwd = random.randint(5, 50)
        duration = random.uniform(50.0, 800.0)

        return {
            "src_ip": src_ip,
            "src_port": random.randint(49152, 65535),
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": "TCP" if dst_port != 53 else "UDP",
            "flow_duration_ms": duration,
            "total_fwd_packets": total_fwd,
            "total_bwd_packets": total_bwd,
            "flow_bytes_per_sec": random.uniform(5000.0, 60000.0),
            "flow_packets_per_sec": random.uniform(20.0, 150.0),
            "flow_iat_mean": random.uniform(10.0, 100.0),
            "flow_iat_std": random.uniform(5.0, 30.0),
            "fwd_packet_length_mean": random.uniform(200.0, 600.0),
            "bwd_packet_length_mean": random.uniform(400.0, 1200.0),
            "packet_length_std": random.uniform(30.0, 90.0),
            "syn_flag_count": 1,
            "fin_flag_count": random.choice([0, 1]),
            "rst_flag_count": 0,
            "psh_flag_count": random.randint(1, 6),
            "ack_flag_count": total_fwd + total_bwd - 2
        }

    def _generate_dos(self) -> Dict[str, Any]:
        attacker_ip = f"185.220.101.{random.randint(2, 250)}"
        total_fwd = random.randint(300, 800)
        return {
            "src_ip": attacker_ip,
            "src_port": random.randint(40000, 65000),
            "dst_ip": "10.0.0.12",
            "dst_port": 80,
            "protocol": "TCP",
            "flow_duration_ms": random.uniform(2.0, 15.0),
            "total_fwd_packets": total_fwd,
            "total_bwd_packets": 0,
            "flow_bytes_per_sec": random.uniform(800000.0, 2000000.0),
            "flow_packets_per_sec": random.uniform(15000.0, 50000.0),
            "flow_iat_mean": random.uniform(0.001, 0.05),
            "flow_iat_std": random.uniform(0.0001, 0.01),
            "fwd_packet_length_mean": 64.0,
            "bwd_packet_length_mean": 0.0,
            "packet_length_std": 0.0,
            "syn_flag_count": total_fwd,
            "fin_flag_count": 0,
            "rst_flag_count": 0,
            "psh_flag_count": 0,
            "ack_flag_count": 0
        }

    def _generate_portscan(self) -> Dict[str, Any]:
        attacker_ip = f"45.154.255.{random.randint(2, 250)}"
        return {
            "src_ip": attacker_ip,
            "src_port": 49152,
            "dst_ip": "10.0.0.12",
            "dst_port": random.randint(1, 65535),
            "protocol": "TCP",
            "flow_duration_ms": random.uniform(0.5, 3.0),
            "total_fwd_packets": 1,
            "total_bwd_packets": 0,
            "flow_bytes_per_sec": random.uniform(3000.0, 8000.0),
            "flow_packets_per_sec": random.uniform(500.0, 1500.0),
            "flow_iat_mean": 0.0,
            "flow_iat_std": 0.0,
            "fwd_packet_length_mean": 44.0,
            "bwd_packet_length_mean": 0.0,
            "packet_length_std": 0.0,
            "syn_flag_count": 1,
            "fin_flag_count": 0,
            "rst_flag_count": 0,
            "psh_flag_count": 0,
            "ack_flag_count": 0
        }

    def _generate_bruteforce(self) -> Dict[str, Any]:
        attacker_ip = f"194.26.29.{random.randint(2, 250)}"
        total_fwd = random.randint(20, 40)
        total_bwd = random.randint(15, 30)
        return {
            "src_ip": attacker_ip,
            "src_port": random.randint(30000, 60000),
            "dst_ip": "10.0.0.12",
            "dst_port": 22,
            "protocol": "TCP",
            "flow_duration_ms": random.uniform(150.0, 300.0),
            "total_fwd_packets": total_fwd,
            "total_bwd_packets": total_bwd,
            "flow_bytes_per_sec": random.uniform(10000.0, 25000.0),
            "flow_packets_per_sec": random.uniform(200.0, 400.0),
            "flow_iat_mean": random.uniform(2.0, 10.0),
            "flow_iat_std": random.uniform(1.0, 5.0),
            "fwd_packet_length_mean": random.uniform(100.0, 150.0),
            "bwd_packet_length_mean": random.uniform(150.0, 220.0),
            "packet_length_std": random.uniform(20.0, 50.0),
            "syn_flag_count": 1,
            "fin_flag_count": 1,
            "rst_flag_count": 0,
            "psh_flag_count": random.randint(6, 12),
            "ack_flag_count": total_fwd + total_bwd - 2
        }

    def _generate_web_attack(self) -> Dict[str, Any]:
        attacker_ip = f"198.51.100.{random.randint(2, 250)}"
        return {
            "src_ip": attacker_ip,
            "src_port": random.randint(30000, 60000),
            "dst_ip": "10.0.0.12",
            "dst_port": 443,
            "protocol": "TCP",
            "flow_duration_ms": random.uniform(300.0, 600.0),
            "total_fwd_packets": random.randint(8, 16),
            "total_bwd_packets": random.randint(3, 8),
            "flow_bytes_per_sec": random.uniform(25000.0, 45000.0),
            "flow_packets_per_sec": random.uniform(30.0, 80.0),
            "flow_iat_mean": random.uniform(20.0, 50.0),
            "flow_iat_std": random.uniform(5.0, 15.0),
            "fwd_packet_length_mean": random.uniform(1200.0, 1600.0),
            "bwd_packet_length_mean": random.uniform(350.0, 550.0),
            "packet_length_std": random.uniform(250.0, 500.0),
            "syn_flag_count": 1,
            "fin_flag_count": 1,
            "rst_flag_count": 0,
            "psh_flag_count": random.randint(3, 6),
            "ack_flag_count": random.randint(10, 20)
        }

    def _generate_botnet(self) -> Dict[str, Any]:
        bot_ip = f"192.0.2.{random.randint(2, 250)}"
        return {
            "src_ip": bot_ip,
            "src_port": random.randint(40000, 60000),
            "dst_ip": "10.0.0.12",
            "dst_port": 6667,
            "protocol": "TCP",
            "flow_duration_ms": random.uniform(30.0, 80.0),
            "total_fwd_packets": 3,
            "total_bwd_packets": 3,
            "flow_bytes_per_sec": random.uniform(4000.0, 8000.0),
            "flow_packets_per_sec": random.uniform(40.0, 80.0),
            "flow_iat_mean": 1000.0,
            "flow_iat_std": 0.05,
            "fwd_packet_length_mean": 128.0,
            "bwd_packet_length_mean": 128.0,
            "packet_length_std": 0.0,
            "syn_flag_count": 1,
            "fin_flag_count": 0,
            "rst_flag_count": 0,
            "psh_flag_count": 1,
            "ack_flag_count": 4
        }

# Global generator instance
traffic_generator = TrafficGenerator()
