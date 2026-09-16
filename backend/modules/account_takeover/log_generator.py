"""
Synthetic Authentication Log Generator.

Generates realistic enterprise authentication events, baseline normal behavior,
and realistic injected threat patterns (impossible travel, brute force, new device).
"""

from datetime import datetime, timedelta, timezone
import random
from typing import Any, Dict, List, Optional
from ...models.schemas import AuthLogEntry

CITIES: Dict[str, Dict[str, Any]] = {
    "San Francisco": {"country": "United States", "lat": 37.7749, "lon": -122.4194, "ip_prefix": "198.51.100."},
    "New York": {"country": "United States", "lat": 40.7128, "lon": -74.0060, "ip_prefix": "192.0.2."},
    "London": {"country": "United Kingdom", "lat": 51.5074, "lon": -0.1278, "ip_prefix": "81.2.69."},
    "Mumbai": {"country": "India", "lat": 19.0760, "lon": 72.8777, "ip_prefix": "103.21.244."},
    "Bangalore": {"country": "India", "lat": 12.9716, "lon": 77.5946, "ip_prefix": "103.15.66."},
    "Tokyo": {"country": "Japan", "lat": 35.6762, "lon": 139.6503, "ip_prefix": "133.242.18."},
    "Frankfurt": {"country": "Germany", "lat": 50.1109, "lon": 8.6821, "ip_prefix": "185.120.44."},
    "Singapore": {"country": "Singapore", "lat": 1.3521, "lon": 103.8198, "ip_prefix": "119.81.200."},
    "Sydney": {"country": "Australia", "lat": -33.8688, "lon": 151.2093, "ip_prefix": "139.130.4."},
    "Moscow": {"country": "Russia", "lat": 55.7558, "lon": 37.6173, "ip_prefix": "95.173.136."},
    "Lagos": {"country": "Nigeria", "lat": 6.5244, "lon": 3.3792, "ip_prefix": "105.112.45."},
    "Bucharest": {"country": "Romania", "lat": 44.4268, "lon": 26.1025, "ip_prefix": "86.120.100."},
}

DEVICE_PROFILES = [
    {
        "name": "corporate_mac",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
        "fingerprint": "fp_mac_chrome_corp_8a92f1",
        "trusted": True
    },
    {
        "name": "corporate_windows",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
        "fingerprint": "fp_win_edge_corp_3c71b9",
        "trusted": True
    },
    {
        "name": "mobile_iphone",
        "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
        "fingerprint": "fp_ios_safari_pers_9e44d0",
        "trusted": True
    },
    {
        "name": "attacker_tor_linux",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "fingerprint": "fp_unknown_linux_tor_0f11a8",
        "trusted": False
    },
    {
        "name": "attacker_headless_bot",
        "user_agent": "python-requests/2.31.0 (Automated Tooling)",
        "fingerprint": "fp_headless_bot_script_77bb4",
        "trusted": False
    }
]


class SyntheticLogGenerator:
    """Generates synthetic authentication logs and injects specific threat patterns."""

    def __init__(self, seed: Optional[int] = 42):
        if seed is not None:
            random.seed(seed)

    def _random_ip(self, prefix: str) -> str:
        return f"{prefix}{random.randint(2, 250)}"

    def generate_normal_baseline(
        self,
        username: str = "alice.smith@enterprise.org",
        city: str = "San Francisco",
        count: int = 5,
        start_time: Optional[datetime] = None
    ) -> List[AuthLogEntry]:
        """Generates regular legitimate authentication logs from a consistent device and location."""
        city_info = CITIES.get(city, CITIES["San Francisco"])
        device = DEVICE_PROFILES[0]  # Corporate Mac
        base_time = start_time or (datetime.now(timezone.utc) - timedelta(hours=count * 3))

        logs: List[AuthLogEntry] = []
        for i in range(count):
            t = base_time + timedelta(hours=i * 3 + random.randint(0, 15) / 60.0)
            logs.append(AuthLogEntry(
                timestamp=t,
                username=username,
                ip_address=self._random_ip(city_info["ip_prefix"]),
                city=city,
                country=city_info["country"],
                latitude=city_info["lat"],
                longitude=city_info["lon"],
                device_fingerprint=device["fingerprint"],
                user_agent=device["user_agent"],
                status="SUCCESS",
                mfa_used=True
            ))
        return logs

    def generate_impossible_travel(
        self,
        username: str = "r.kapoor@globalfin.com",
        origin_city: str = "Mumbai",
        dest_city: str = "London",
        time_delta_minutes: int = 12
    ) -> List[AuthLogEntry]:
        """
        Generates normal login in origin city followed in rapid succession
        by a login in destination city thousands of kilometers away.
        """
        now = datetime.now(timezone.utc)
        origin_info = CITIES[origin_city]
        dest_info = CITIES[dest_city]
        primary_dev = DEVICE_PROFILES[0]
        attacker_dev = DEVICE_PROFILES[3]

        t1 = now - timedelta(minutes=time_delta_minutes + 15)
        t2 = now - timedelta(minutes=time_delta_minutes)
        t3 = now  # The impossible travel login

        logs = [
            AuthLogEntry(
                timestamp=t1,
                username=username,
                ip_address=self._random_ip(origin_info["ip_prefix"]),
                city=origin_city,
                country=origin_info["country"],
                latitude=origin_info["lat"],
                longitude=origin_info["lon"],
                device_fingerprint=primary_dev["fingerprint"],
                user_agent=primary_dev["user_agent"],
                status="SUCCESS",
                mfa_used=True
            ),
            AuthLogEntry(
                timestamp=t2,
                username=username,
                ip_address=self._random_ip(origin_info["ip_prefix"]),
                city=origin_city,
                country=origin_info["country"],
                latitude=origin_info["lat"],
                longitude=origin_info["lon"],
                device_fingerprint=primary_dev["fingerprint"],
                user_agent=primary_dev["user_agent"],
                status="SUCCESS",
                mfa_used=True
            ),
            AuthLogEntry(
                timestamp=t3,
                username=username,
                ip_address=self._random_ip(dest_info["ip_prefix"]),
                city=dest_city,
                country=dest_info["country"],
                latitude=dest_info["lat"],
                longitude=dest_info["lon"],
                device_fingerprint=attacker_dev["fingerprint"],
                user_agent=attacker_dev["user_agent"],
                status="SUCCESS",
                mfa_used=False
            )
        ]
        return logs

    def generate_brute_force(
        self,
        username: str = "admin@banktech.corp",
        city: str = "Moscow",
        failed_attempts: int = 12,
        final_success: bool = True
    ) -> List[AuthLogEntry]:
        """
        Generates rapid burst of failed authentications from an attacker IP,
        optionally concluding with a compromised success.
        """
        now = datetime.now(timezone.utc)
        city_info = CITIES[city]
        attacker_dev = DEVICE_PROFILES[4]  # Headless bot / Script
        ip = self._random_ip(city_info["ip_prefix"])

        logs: List[AuthLogEntry] = []
        start_time = now - timedelta(seconds=(failed_attempts + 2) * 8)

        for i in range(failed_attempts):
            t = start_time + timedelta(seconds=i * 8 + random.uniform(0.5, 3.0))
            logs.append(AuthLogEntry(
                timestamp=t,
                username=username,
                ip_address=ip,
                city=city,
                country=city_info["country"],
                latitude=city_info["lat"],
                longitude=city_info["lon"],
                device_fingerprint=attacker_dev["fingerprint"],
                user_agent=attacker_dev["user_agent"],
                status="FAILURE",
                mfa_used=False
            ))

        if final_success:
            logs.append(AuthLogEntry(
                timestamp=start_time + timedelta(seconds=(failed_attempts + 1) * 8),
                username=username,
                ip_address=ip,
                city=city,
                country=city_info["country"],
                latitude=city_info["lat"],
                longitude=city_info["lon"],
                device_fingerprint=attacker_dev["fingerprint"],
                user_agent=attacker_dev["user_agent"],
                status="SUCCESS",
                mfa_used=False
            ))

        return logs

    def generate_new_device_hijack(
        self,
        username: str = "dev.lead@okcl.org.in",
        home_city: str = "Bangalore",
        attacker_city: str = "Bucharest"
    ) -> List[AuthLogEntry]:
        """
        Legitimate baseline activity on trusted Mac, followed by sudden login
        on untrusted device in unfamiliar location without MFA.
        """
        home_info = CITIES[home_city]
        attacker_info = CITIES[attacker_city]
        home_dev = DEVICE_PROFILES[0]
        attacker_dev = DEVICE_PROFILES[3]
        now = datetime.now(timezone.utc)

        logs = [
            AuthLogEntry(
                timestamp=now - timedelta(hours=24),
                username=username,
                ip_address=self._random_ip(home_info["ip_prefix"]),
                city=home_city,
                country=home_info["country"],
                latitude=home_info["lat"],
                longitude=home_info["lon"],
                device_fingerprint=home_dev["fingerprint"],
                user_agent=home_dev["user_agent"],
                status="SUCCESS",
                mfa_used=True
            ),
            AuthLogEntry(
                timestamp=now - timedelta(hours=6),
                username=username,
                ip_address=self._random_ip(home_info["ip_prefix"]),
                city=home_city,
                country=home_info["country"],
                latitude=home_info["lat"],
                longitude=home_info["lon"],
                device_fingerprint=home_dev["fingerprint"],
                user_agent=home_dev["user_agent"],
                status="SUCCESS",
                mfa_used=True
            ),
            # Attacker fails once, then succeeds with stolen password
            AuthLogEntry(
                timestamp=now - timedelta(minutes=4),
                username=username,
                ip_address=self._random_ip(attacker_info["ip_prefix"]),
                city=attacker_city,
                country=attacker_info["country"],
                latitude=attacker_info["lat"],
                longitude=attacker_info["lon"],
                device_fingerprint=attacker_dev["fingerprint"],
                user_agent=attacker_dev["user_agent"],
                status="FAILURE",
                mfa_used=False
            ),
            AuthLogEntry(
                timestamp=now,
                username=username,
                ip_address=self._random_ip(attacker_info["ip_prefix"]),
                city=attacker_city,
                country=attacker_info["country"],
                latitude=attacker_info["lat"],
                longitude=attacker_info["lon"],
                device_fingerprint=attacker_dev["fingerprint"],
                user_agent=attacker_dev["user_agent"],
                status="SUCCESS",
                mfa_used=False
            )
        ]
        return logs

    def generate(
        self,
        username: str = "sarah.connor@cyberguard.internal",
        count: int = 10,
        anomaly_type: str = "impossible_travel"
    ) -> List[AuthLogEntry]:
        """Dynamic generator for API and testing."""
        if anomaly_type == "impossible_travel":
            baseline = self.generate_normal_baseline(username=username, city="San Francisco", count=max(2, count - 3))
            travel = self.generate_impossible_travel(username=username, origin_city="San Francisco", dest_city="London", time_delta_minutes=15)
            # Combine
            return sorted(baseline + travel, key=lambda x: x.timestamp)
        elif anomaly_type == "brute_force":
            baseline = self.generate_normal_baseline(username=username, city="New York", count=2)
            bf = self.generate_brute_force(username=username, city="Moscow", failed_attempts=max(5, count - 3))
            return sorted(baseline + bf, key=lambda x: x.timestamp)
        elif anomaly_type == "new_device":
            return self.generate_new_device_hijack(username=username)
        else:
            return self.generate_normal_baseline(username=username, city="San Francisco", count=count)
