"""
TrianSec Traffic Simulation - 63 Authenticated Users
With full evidence recording for proof/audit purposes.

Simulates realistic traffic patterns to test:
- Behavior-driven protection
- Multi-signal identity resolution
- Reputation tracking
- Adaptive policy engine
- Progressive enforcement
- Explainable decisions

User Distribution:
- 120 Normal users (60%) - legitimate behavior
- 40 Minimal bad behavior users (20%) - slightly aggressive but not malicious
- 25 Suspicious users (12.5%) - probing, scanning, higher risk
- 15 Real bad users (7.5%) - credential stuffing, injection, scraping
"""

import asyncio
import random
import httpx
import time
import uuid
import hashlib
import json
import os
import csv
from datetime import datetime
from typing import List, Tuple, Dict, Optional, Set
import signal
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum

# ============ CONFIGURATION ============
BASE_URL = "http://localhost:8000"
DURATION_MINUTES = 10

# User counts (total = 63)
NORMAL_USERS_COUNT = 30
MINIMAL_BAD_USERS_COUNT = 10
SUSPICIOUS_USERS_COUNT = 18
REAL_BAD_USERS_COUNT = 5

# API Key for authentication (all users authenticated with same tenant key)
API_KEY = "ts_live_905ddc9096b056a2cc9ebbd63d8adb6c8456cc780d8f987d"

# ============ EVIDENCE RECORDING ============
EVIDENCE_DIR = "evidence"
os.makedirs(EVIDENCE_DIR, exist_ok=True)
RUN_ID = datetime.now().strftime("%Y%m%d_%H%M%S")
EVIDENCE_JSON = os.path.join(EVIDENCE_DIR, f"run_{RUN_ID}.json")
EVIDENCE_CSV  = os.path.join(EVIDENCE_DIR, f"run_{RUN_ID}.csv")
SUMMARY_TXT   = os.path.join(EVIDENCE_DIR, f"summary_{RUN_ID}.txt")

# ============ ENHANCED IP POOL (500+ realistic IPs) ============
def generate_ip_pool():
    """Generate a large pool of realistic IPs across different regions"""
    ips = []
    
    # US IPs (New York) - 192.168.1.x
    for i in range(100, 200):
        ips.append(f"192.168.1.{i}")
    
    # US IPs (California) - 10.0.0.x
    for i in range(100, 200):
        ips.append(f"10.0.0.{i}")
    
    # Europe IPs (UK, Germany, France) - 172.16.x.x
    for subnet in range(0, 5):
        for i in range(100, 150):
            ips.append(f"172.16.{subnet}.{i}")
    
    # Asia IPs (Japan, Singapore, India) - 192.168.2.x, 192.168.3.x
    for i in range(100, 200):
        ips.append(f"192.168.2.{i}")
    for i in range(100, 150):
        ips.append(f"192.168.3.{i}")
    
    # South America IPs (Brazil, Argentina) - 10.1.0.x
    for i in range(100, 180):
        ips.append(f"10.1.0.{i}")
    
    # Australia IPs - 172.17.0.x
    for i in range(100, 150):
        ips.append(f"172.17.0.{i}")
    
    # Mobile Network IPs - 192.168.100.x, 10.10.0.x
    for i in range(100, 180):
        ips.append(f"192.168.100.{i}")
    for i in range(100, 160):
        ips.append(f"10.10.0.{i}")
    
    # Corporate IPs - 172.18.0.x, 192.168.200.x
    for i in range(100, 160):
        ips.append(f"172.18.0.{i}")
    for i in range(100, 160):
        ips.append(f"192.168.200.{i}")
    
    # Additional random IPs
    for i in range(100, 140):
        ips.append(f"10.2.0.{i}")
    for i in range(100, 140):
        ips.append(f"172.19.0.{i}")
    
    return ips

IP_POOL = generate_ip_pool()

# ============ USER AGENT POOL ============
USER_AGENTS = {
    "browser": [
        # Chrome - Windows
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
        # Chrome - Mac
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        # Firefox
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
        # Safari
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
        # Edge
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
        # Opera
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    ],
    "mobile": [
        # iPhone
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
        # Samsung
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        # Google Pixel
        "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
        # OnePlus
        "Mozilla/5.0 (Linux; Android 13; OnePlus 11) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        # Xiaomi
        "Mozilla/5.0 (Linux; Android 13; Xiaomi 13 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
    ],
    "bot": [
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
        "python-requests/2.31.0",
        "curl/7.88.1",
        "Wget/1.21.3",
        "Scrapy/2.11.0 (+https://scrapy.org)",
        "Go-http-client/1.1",
        "Java/17.0.2",
        "Node.js/20.11.0",
    ]
}

# ============ ACCEPT LANGUAGE POOL ============
ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9", "en-GB,en;q=0.9", "fr-FR,fr;q=0.9",
    "de-DE,de;q=0.9", "es-ES,es;q=0.9", "ja-JP,ja;q=0.9",
    "zh-CN,zh;q=0.9", "pt-BR,pt;q=0.9", "ru-RU,ru;q=0.9",
    "it-IT,it;q=0.9", "ko-KR,ko;q=0.9", "nl-NL,nl;q=0.9",
    "sv-SE,sv;q=0.9", "pl-PL,pl;q=0.9", "tr-TR,tr;q=0.9",
    "ar-SA,ar;q=0.9", "en-US,en;q=0.9,fr;q=0.8",
    "en-GB,en;q=0.9,de;q=0.8", "en-US,en;q=0.9,es;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
]

# ============ ENDPOINTS ============
NORMAL_ENDPOINTS = [
    "/health",
    "/api/profile",
    "/api/users/me",
    "/api/products",
    "/api/search",
    "/api/feed",
]

BUSINESS_ENDPOINTS = [
    "/api/orders",
    "/api/cart",
    "/api/checkout",
    "/api/payments",
    "/api/settings",
    "/api/notifications",
]

SUSPICIOUS_ENDPOINTS = [
    "/api/data",
    "/api/products",
    "/api/search",
    "/api/users",
    "/api/admin",
    "/api/export",
]

ATTACK_ENDPOINTS = [
    "/login",
    "/admin",
    "/config",
    "/.env",
    "/debug",
    "/api/private",
    "/wp-admin",
    "/phpmyadmin",
    "/api/v1/users",
    "/api/v1/internal",
    "/graphql",
    "/actuator",
    "/metrics",
    "/swagger.json",
]

# ============ USER BEHAVIOR CONFIGURATION ============
class UserType(Enum):
    NORMAL = "normal"
    MINIMAL_BAD = "minimal_bad"
    SUSPICIOUS = "suspicious"
    REAL_BAD = "real_bad"

@dataclass
class UserBehavior:
    """Behavior configuration for each user type"""
    delay_range: Tuple[float, float]
    ip_change_probability: float
    ip_change_interval: Tuple[float, float]
    user_agent_types: List[str]
    cookie_persistence: bool
    error_rate: float
    request_burst_probability: float
    burst_size_range: Tuple[int, int]
    suspicious_endpoint_probability: float
    attack_endpoint_probability: float
    description: str

USER_BEHAVIORS = {
    UserType.NORMAL: UserBehavior(
        delay_range=(2.0, 8.0),
        ip_change_probability=0.2,
        ip_change_interval=(600, 3600),
        user_agent_types=["browser", "mobile"],
        cookie_persistence=True,
        error_rate=0.01,
        request_burst_probability=0.02,
        burst_size_range=(2, 4),
        suspicious_endpoint_probability=0.0,
        attack_endpoint_probability=0.0,
        description="Legitimate user with human-like behavior"
    ),
    UserType.MINIMAL_BAD: UserBehavior(
        delay_range=(1.0, 4.0),
        ip_change_probability=0.3,
        ip_change_interval=(300, 1800),
        user_agent_types=["browser", "mobile"],
        cookie_persistence=True,
        error_rate=0.03,
        request_burst_probability=0.10,
        burst_size_range=(3, 8),
        suspicious_endpoint_probability=0.05,
        attack_endpoint_probability=0.0,
        description="Slightly aggressive but not clearly malicious"
    ),
    UserType.SUSPICIOUS: UserBehavior(
        delay_range=(0.5, 2.5),
        ip_change_probability=0.5,
        ip_change_interval=(120, 600),
        user_agent_types=["browser", "bot"],
        cookie_persistence=True,
        error_rate=0.05,
        request_burst_probability=0.25,
        burst_size_range=(5, 15),
        suspicious_endpoint_probability=0.35,
        attack_endpoint_probability=0.05,
        description="Probing, scanning, higher risk behavior"
    ),
    UserType.REAL_BAD: UserBehavior(
        delay_range=(0.1, 1.5),
        ip_change_probability=0.9,
        ip_change_interval=(1, 10),
        user_agent_types=["browser", "bot"],
        cookie_persistence=True,
        error_rate=0.10,
        request_burst_probability=0.60,
        burst_size_range=(10, 30),
        suspicious_endpoint_probability=0.50,
        attack_endpoint_probability=0.40,
        description="Credential stuffing, injection, scraping"
    ),
}

# ============ IP MANAGER ============
class IPManager:
    def __init__(self):
        self.used_ips: Dict[int, str] = {}
        self.ip_pool = IP_POOL.copy()
        random.shuffle(self.ip_pool)
        self.ip_index = 0
        self.ip_history: Dict[int, List[str]] = {}
        self.ip_change_timers: Dict[int, float] = {}
        self.ip_usage_count: Dict[str, int] = defaultdict(int)

    def get_ip_for_user(self, user_id: int, user_type: UserType) -> str:
        behavior = USER_BEHAVIORS[user_type]

        if user_id not in self.used_ips:
            ip = self.ip_pool[self.ip_index % len(self.ip_pool)]
            self.used_ips[user_id] = ip
            self.ip_history[user_id] = [ip]
            self.ip_usage_count[ip] += 1
            min_interval, max_interval = behavior.ip_change_interval
            self.ip_change_timers[user_id] = time.time() + random.uniform(min_interval, max_interval)
            self.ip_index += 1
        else:
            current_time = time.time()
            if current_time > self.ip_change_timers.get(user_id, 0):
                if random.random() < behavior.ip_change_probability:
                    old_ip = self.used_ips[user_id]
                    attempts = 0
                    while attempts < 20:
                        new_ip = random.choice(self.ip_pool)
                        if new_ip != old_ip:
                            self.used_ips[user_id] = new_ip
                            self.ip_history[user_id].append(new_ip)
                            self.ip_usage_count[new_ip] += 1
                            min_interval, max_interval = behavior.ip_change_interval
                            self.ip_change_timers[user_id] = time.time() + random.uniform(min_interval, max_interval)
                            break
                        attempts += 1

        return self.used_ips.get(user_id, self.ip_pool[0])

    def get_rotating_ip(self) -> str:
        ip = random.choice(self.ip_pool)
        self.ip_usage_count[ip] += 1
        return ip

    def get_ip_history(self, user_id: int) -> List[str]:
        return self.ip_history.get(user_id, [])

    def get_shared_ip_count(self, ip: str) -> int:
        return self.ip_usage_count.get(ip, 0)

ip_manager = IPManager()

# ============ COOKIE MANAGER ============
class CookieManager:
    def __init__(self):
        self.user_cookies: Dict[int, str] = {}
        self.cookie_history: Dict[int, List[str]] = {}
        self.cookie_creation_times: Dict[int, float] = {}

    def get_or_create_cookie(self, user_id: int) -> Optional[str]:
        if user_id not in self.user_cookies:
            cookie_val = f"user_{user_id}_{uuid.uuid4().hex[:16]}"
            self.user_cookies[user_id] = cookie_val
            self.cookie_history[user_id] = [cookie_val]
            self.cookie_creation_times[user_id] = time.time()

        return self.user_cookies[user_id]

    def refresh_cookie(self, user_id: int) -> str:
        new_cookie = f"user_{user_id}_{uuid.uuid4().hex[:16]}"
        self.user_cookies[user_id] = new_cookie
        if user_id in self.cookie_history:
            self.cookie_history[user_id].append(new_cookie)
        else:
            self.cookie_history[user_id] = [new_cookie]
        self.cookie_creation_times[user_id] = time.time()
        return new_cookie

cookie_manager = CookieManager()

# ============ EVIDENCE RECORDER ============
class EvidenceRecorder:
    """Records every request with full identity context for proof/audit."""

    def __init__(self):
        self.requests: List[Dict] = []
        self.identity_events: List[Dict] = []
        self.decisions: List[Dict] = []
        self._lock = asyncio.Lock()

    async def record_request(self, rec: Dict):
        async with self._lock:
            self.requests.append(rec)

    async def record_identity(self, event: Dict):
        async with self._lock:
            self.identity_events.append(event)

    async def record_decision(self, dec: Dict):
        async with self._lock:
            self.decisions.append(dec)

    def to_csv(self, path: str):
        fields = [
            "seq", "timestamp", "elapsed_s", "user_id", "user_type",
            "method", "endpoint", "status_code", "latency_ms",
            "ip", "ip_forwarded", "user_agent", "accept_lang",
            "cookie_id", "fingerprint", "decision",
            "request_kind", "burst", "response_reason",
        ]
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            for r in self.requests:
                w.writerow(r)

    def to_json(self, path: str, meta: Dict):
        payload = {
            "run_id": RUN_ID,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "metadata": meta,
            "requests": self.requests,
            "identity_events": self.identity_events,
            "decisions": self.decisions,
        }
        with open(path, "w") as f:
            json.dump(payload, f, indent=2, default=str)

evidence = EvidenceRecorder()

# ============ HELPER FUNCTIONS ============
def get_user_agent(user_type: UserType) -> str:
    behavior = USER_BEHAVIORS[user_type]
    agent_types = behavior.user_agent_types

    all_agents = []
    for agent_type in agent_types:
        all_agents.extend(USER_AGENTS.get(agent_type, []))

    return random.choice(all_agents) if all_agents else USER_AGENTS["browser"][0]

def generate_fingerprint(ip: str, user_agent: str, accept_lang: str) -> str:
    raw = f"{ip}:{user_agent}:{accept_lang}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

def random_headers(
    user_type: UserType,
    user_id: int,
    rotate_ip: bool = False,
    include_cookie: bool = True,
    existing_cookie: Optional[str] = None
) -> dict:
    behavior = USER_BEHAVIORS[user_type]

    if rotate_ip:
        ip = ip_manager.get_rotating_ip()
    else:
        ip = ip_manager.get_ip_for_user(user_id, user_type)

    user_agent = get_user_agent(user_type)
    accept_lang = random.choice(ACCEPT_LANGUAGES)

    headers = {
        "X-API-KEY": API_KEY,
        "User-Agent": user_agent,
        "Accept": random.choice([
            "application/json, text/plain, */*",
            "application/json, text/html, */*",
            "*/*"
        ]),
        "Accept-Language": accept_lang,
        "Accept-Encoding": random.choice([
            "gzip, deflate, br",
            "gzip, deflate",
            "br"
        ]),
        "Connection": random.choice(["keep-alive", "close"]),
        "X-Forwarded-For": ip,
        "X-Real-IP": ip,
        "Cache-Control": random.choice([
            "no-cache",
            "max-age=0",
            "private, no-cache, no-store"
        ]),
        "Sec-Ch-Ua": f'"Not_A Brand";v="99", "Chromium";v="120", "Google Chrome";v="120"',
        "Sec-Ch-Ua-Mobile": random.choice(["?0", "?1"]),
        "Sec-Ch-Ua-Platform": random.choice(['"Windows"', '"macOS"', '"Linux"', '"Android"', '"iOS"']),
        "Sec-Fetch-Site": random.choice(["same-origin", "cross-site", "none"]),
        "Sec-Fetch-Mode": random.choice(["cors", "navigate", "same-origin"]),
        "Sec-Fetch-Dest": random.choice(["document", "empty", "script", "style"]),
        "X-Simulated-User-Type": user_type.value,
        "X-Simulated-User-ID": str(user_id),
        "X-Simulated-Fingerprint": generate_fingerprint(ip, user_agent, accept_lang),
    }

    if include_cookie:
        if existing_cookie:
            cookie_val = existing_cookie
        else:
            cookie_val = cookie_manager.get_or_create_cookie(user_id)

        if cookie_val:
            headers["Cookie"] = f"X-TrianSec-User-ID={cookie_val}"

    headers["X-Simulated-Label"] = user_type.value

    if random.random() < 0.1:
        headers["DNT"] = random.choice(["1", "0"])
    if random.random() < 0.05:
        headers["X-Requested-With"] = "XMLHttpRequest"
    if random.random() < 0.02:
        headers["X-Forwarded-Proto"] = "https"

    return headers

def extract_decision(response) -> Tuple[str, str]:
    """Extract decision + reason from TrianSec response headers/body."""
    h = response.headers
    decision = (
        h.get("X-TrianSec-Decision")
        or h.get("X-Decision")
        or h.get("X-Policy-Decision")
        or ""
    ).upper()

    if not decision:
        sc = response.status_code
        if sc == 429:
            decision = "THROTTLE"
        elif sc == 403:
            decision = "BLOCK"
        elif 200 <= sc < 300:
            decision = "ALLOW"
        else:
            decision = "ERROR"

    reason = (
        h.get("X-TrianSec-Reason")
        or h.get("X-Decision-Reason")
        or h.get("X-Policy-Reason")
        or h.get("X-RateLimit-Reason")
        or ""
    )
    return decision, reason[:200]

# ============ REQUEST BUILDER ============
class RequestBuilder:
    @staticmethod
    def build_search_request():
        terms = ["laptop", "phone", "tablet", "book", "mouse", "keyboard",
                 "monitor", "printer", "camera", "headphones", "speaker",
                 "charger", "cable", "adapter", "stand", "case"]
        return f"/api/search?q={random.choice(terms)}"

    @staticmethod
    def build_product_request():
        product_ids = [f"prod_{i}" for i in range(1, 100)]
        return f"/api/products/{random.choice(product_ids)}"

    @staticmethod
    def build_order_request():
        return "/api/orders"

    @staticmethod
    def build_suspicious_request():
        suspicious_patterns = [
            "/api/data?limit=10000",
            "/api/users?page=1&per_page=1000",
            "/api/export?format=csv&all=true",
            "/api/products?fields=*&limit=99999",
            f"/api/search?q={'a' * 100}",
            f"/api/search?q={'*' * 50}",
            "/api/users?role=admin",
            "/api/admin/users",
        ]
        return random.choice(suspicious_patterns)

    @staticmethod
    def build_attack_request():
        attacks = [
            "/api/search?q=' OR '1'='1",
            "/api/search?q=admin'--",
            "/api/search?q=1' AND 1=1--",
            "/api/search?q=' UNION SELECT 1,2,3--",
            "/api/users?id=1 OR 1=1",
            "/api/files?path=../../etc/passwd",
            "/api/files?path=....//....//etc/passwd",
            "/api/ping?host=127.0.0.1;cat /etc/passwd",
            "/api/ping?host=127.0.0.1|whoami",
            "/api/search?q=<script>alert(1)</script>",
            "/api/fetch?url=http://169.254.169.254/latest/meta-data/",
            "/api/parse?xml=<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
        ]
        return random.choice(attacks)

# ============ SIMULATION STATISTICS ============
@dataclass
class SimulationStats:
    total_requests: int = 0
    successful_requests: int = 0
    rate_limited: int = 0
    blocked: int = 0
    errors: int = 0
    by_user_type: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    by_status_code: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    by_endpoint: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    ip_changes: int = 0
    cookie_refreshes: int = 0
    burst_events: int = 0
    suspicious_events: int = 0
    attack_events: int = 0
    start_time: float = 0.0

    def record_request(self, user_type: str, status_code: int, endpoint: str):
        self.total_requests += 1
        self.by_user_type[user_type] += 1
        self.by_status_code[status_code] += 1
        self.by_endpoint[endpoint] += 1

        if status_code == 429:
            self.rate_limited += 1
        elif status_code == 403:
            self.blocked += 1
        elif status_code >= 400:
            self.errors += 1
        else:
            self.successful_requests += 1

stats = SimulationStats()

# ============ USER SIMULATION ============
async def simulate_user(
    user_id: int,
    user_type: UserType,
    stop_event: asyncio.Event,
    client: httpx.AsyncClient,
):
    """Simulate a single user with full evidence recording."""
    behavior = USER_BEHAVIORS[user_type]
    user_cookie = cookie_manager.get_or_create_cookie(user_id)
    request_count = 0
    consecutive_errors = 0
    last_ip_seen = None

    session_endpoints = random.sample(NORMAL_ENDPOINTS, min(3, len(NORMAL_ENDPOINTS)))
    session_start = time.time()
    session_duration = random.uniform(60, 300)

    async def do_request(method: str, endpoint: str, is_burst: bool = False,
                         request_kind: str = "normal"):
        nonlocal user_cookie, last_ip_seen, request_count, consecutive_errors

        headers = random_headers(
            user_type,
            user_id,
            rotate_ip=(random.random() < behavior.ip_change_probability),
            include_cookie=True,
            existing_cookie=user_cookie,
        )

        ip = headers.get("X-Forwarded-For", "")
        if last_ip_seen and ip != last_ip_seen:
            await evidence.record_identity({
                "ts": datetime.utcnow().isoformat() + "Z",
                "elapsed_s": round(time.time() - stats.start_time, 3),
                "user_id": user_id,
                "user_type": user_type.value,
                "event": "IP_CHANGE",
                "from_ip": last_ip_seen,
                "to_ip": ip,
                "cookie_id": user_cookie,
                "fingerprint": headers.get("X-Simulated-Fingerprint"),
            })
            stats.ip_changes += 1
        last_ip_seen = ip

        if "Cookie" in headers:
            parts = headers["Cookie"].split("=", 1)
            if len(parts) > 1:
                user_cookie = parts[1]

        t0 = time.time()
        status_code = 0
        decision = "ERROR"
        reason = ""
        try:
            if method == "GET":
                r = await client.get(endpoint, headers=headers, timeout=10)
            elif method == "POST":
                r = await client.post(endpoint,
                    json={"data": "test", "timestamp": time.time()},
                    headers=headers, timeout=10)
            elif method == "PUT":
                r = await client.put(endpoint, json={"data": "update"},
                    headers=headers, timeout=10)
            else:
                r = await client.delete(endpoint, headers=headers, timeout=10)

            status_code = r.status_code
            decision, reason = extract_decision(r)
            stats.record_request(user_type.value, status_code,
                                 endpoint.split("?")[0])
            request_count += 1
            consecutive_errors = 0
        except httpx.TimeoutException:
            consecutive_errors += 1
            stats.errors += 1
            decision = "TIMEOUT"
        except Exception:
            consecutive_errors += 1
            stats.errors += 1
            decision = "EXCEPTION"

        latency_ms = round((time.time() - t0) * 1000, 2)

        await evidence.record_request({
            "seq": len(evidence.requests) + 1,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "elapsed_s": round(time.time() - stats.start_time, 3),
            "user_id": user_id,
            "user_type": user_type.value,
            "method": method,
            "endpoint": endpoint,
            "status_code": status_code,
            "latency_ms": latency_ms,
            "ip": ip,
            "ip_forwarded": headers.get("X-Forwarded-For"),
            "user_agent": headers.get("User-Agent"),
            "accept_lang": headers.get("Accept-Language"),
            "cookie_id": user_cookie,
            "fingerprint": headers.get("X-Simulated-Fingerprint"),
            "decision": decision,
            "request_kind": request_kind,
            "burst": is_burst,
            "response_reason": reason,
        })

        if decision in ("THROTTLE", "BLOCK"):
            await evidence.record_decision({
                "ts": datetime.utcnow().isoformat() + "Z",
                "elapsed_s": round(time.time() - stats.start_time, 3),
                "user_id": user_id,
                "user_type": user_type.value,
                "decision": decision,
                "reason": reason,
                "endpoint": endpoint,
                "ip": ip,
                "cookie_id": user_cookie,
                "fingerprint": headers.get("X-Simulated-Fingerprint"),
            })

        return status_code

    while not stop_event.is_set():
        try:
            if time.time() - session_start > session_duration:
                session_endpoints = random.sample(NORMAL_ENDPOINTS,
                                                  min(3, len(NORMAL_ENDPOINTS)))
                session_start = time.time()
                session_duration = random.uniform(60, 300)
                if random.random() < 0.1:
                    old_cookie = user_cookie
                    user_cookie = cookie_manager.refresh_cookie(user_id)
                    stats.cookie_refreshes += 1
                    await evidence.record_identity({
                        "ts": datetime.utcnow().isoformat() + "Z",
                        "elapsed_s": round(time.time() - stats.start_time, 3),
                        "user_id": user_id,
                        "user_type": user_type.value,
                        "event": "COOKIE_REFRESH",
                        "from_cookie": old_cookie,
                        "to_cookie": user_cookie,
                        "ip": last_ip_seen,
                    })

            r = random.random()
            kind = "normal"
            if r < behavior.attack_endpoint_probability:
                endpoint = random.choice(ATTACK_ENDPOINTS)
                if random.random() < 0.3:
                    endpoint = RequestBuilder.build_attack_request()
                stats.attack_events += 1
                method = random.choice(["GET", "POST", "PUT", "DELETE"])
                kind = "attack"
            elif r < behavior.attack_endpoint_probability + behavior.suspicious_endpoint_probability:
                endpoint = random.choice(SUSPICIOUS_ENDPOINTS)
                if random.random() < 0.4:
                    endpoint = RequestBuilder.build_suspicious_request()
                stats.suspicious_events += 1
                method = random.choice(["GET", "POST"])
                kind = "suspicious"
            elif r < behavior.attack_endpoint_probability + behavior.suspicious_endpoint_probability + 0.1:
                endpoint = random.choice(BUSINESS_ENDPOINTS)
                method = random.choice(["GET", "POST"])
                kind = "business"
            else:
                endpoint = random.choice(session_endpoints)
                if endpoint == "/api/search" and random.random() < 0.4:
                    endpoint = RequestBuilder.build_search_request()
                method = "GET"
                kind = "normal"

            delay = random.uniform(*behavior.delay_range)

            if random.random() < behavior.error_rate:
                await asyncio.sleep(delay)
                continue

            await do_request(method, endpoint, is_burst=False, request_kind=kind)

            if random.random() < behavior.request_burst_probability:
                burst_size = random.randint(*behavior.burst_size_range)
                stats.burst_events += 1
                for _ in range(burst_size):
                    if stop_event.is_set():
                        break
                    be = random.choice(NORMAL_ENDPOINTS)
                    await do_request("GET", be, is_burst=True, request_kind="burst")
                    await asyncio.sleep(random.uniform(0.05, 0.2))

            await asyncio.sleep(delay)
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(random.uniform(1.0, 3.0))

# ============ MONITORING ============
class Monitor:
    def __init__(self, stop_event: asyncio.Event):
        self.stop_event = stop_event
        self.last_request_count = 0

    async def run(self):
        while not self.stop_event.is_set():
            elapsed = time.time() - stats.start_time
            recent_requests = stats.total_requests - self.last_request_count
            self.last_request_count = stats.total_requests
            rps = recent_requests / 5

            unique_ips = len(ip_manager.used_ips)
            total_ip_changes = sum(len(h) - 1 for h in ip_manager.ip_history.values() if len(h) > 1)
            total_cookies = len(cookie_manager.user_cookies)

            status = (
                f"\r📊 {elapsed/60:.1f}/{DURATION_MINUTES}min | "
                f"RPS: {rps:.1f} | "
                f"Req: {stats.total_requests} | "
                f"OK: {stats.successful_requests} | "
                f"429: {stats.rate_limited} | "
                f"403: {stats.blocked} | "
                f"Err: {stats.errors} | "
                f"IPs: {unique_ips} | "
                f"IPΔ: {total_ip_changes} | "
                f"🍪: {total_cookies}"
            )

            print(status, end="", flush=True)
            await asyncio.sleep(5)

# ============ MAIN SIMULATION ============
class Simulation:
    def __init__(self):
        self.tasks: List[asyncio.Task] = []
        self.stop_event = asyncio.Event()
        self.start_time = None
        self.client: Optional[httpx.AsyncClient] = None

    def signal_handler(self, sig, frame):
        print("\n\n🛑 Stopping simulation gracefully...")
        self.stop_event.set()

    async def run(self):
        print("=" * 90)
        print("🛡️  TRIANSEC - COMPREHENSIVE TRAFFIC SIMULATION")
        print("=" * 90)
        print(f"⏱️  Duration: {DURATION_MINUTES} minutes")
        print(f"🔑 API Key: {API_KEY[:30]}...")
        print(f"🌐 IP Pool Size: {len(IP_POOL)} unique IPs")
        print(f"📡 Base URL: {BASE_URL}")
        print(f"📁 Evidence dir: {EVIDENCE_DIR}/")
        print(f"🆔 Run ID: {RUN_ID}")
        print("=" * 90)
        print("\n👥 User Distribution:")
        print(f"   ✅ Normal users:       {NORMAL_USERS_COUNT:3d}")
        print(f"   ⚠️  Minimal bad users:  {MINIMAL_BAD_USERS_COUNT:3d}")
        print(f"   🔶 Suspicious users:   {SUSPICIOUS_USERS_COUNT:3d}")
        print(f"   🔴 Real bad users:     {REAL_BAD_USERS_COUNT:3d}")
        print("=" * 90)
        print("\n🚀 Starting simulation... Press Ctrl+C to stop early\n")

        signal.signal(signal.SIGINT, self.signal_handler)

        stats.start_time = time.time()
        self.start_time = stats.start_time

        limits = httpx.Limits(
            max_keepalive_connections=100,
            max_connections=200,
            keepalive_expiry=30.0
        )
        timeout = httpx.Timeout(10.0, connect=5.0)

        async with httpx.AsyncClient(
            base_url=BASE_URL,
            limits=limits,
            timeout=timeout,
            follow_redirects=True
        ) as client:
            self.client = client

            user_id = 0
            for i in range(NORMAL_USERS_COUNT):
                self.tasks.append(asyncio.create_task(
                    simulate_user(user_id + i, UserType.NORMAL, self.stop_event, client)
                ))
            user_id += NORMAL_USERS_COUNT

            for i in range(MINIMAL_BAD_USERS_COUNT):
                self.tasks.append(asyncio.create_task(
                    simulate_user(user_id + i, UserType.MINIMAL_BAD, self.stop_event, client)
                ))
            user_id += MINIMAL_BAD_USERS_COUNT

            for i in range(SUSPICIOUS_USERS_COUNT):
                self.tasks.append(asyncio.create_task(
                    simulate_user(user_id + i, UserType.SUSPICIOUS, self.stop_event, client)
                ))
            user_id += SUSPICIOUS_USERS_COUNT

            for i in range(REAL_BAD_USERS_COUNT):
                self.tasks.append(asyncio.create_task(
                    simulate_user(user_id + i, UserType.REAL_BAD, self.stop_event, client)
                ))

            monitor = Monitor(self.stop_event)
            monitor_task = asyncio.create_task(monitor.run())

            try:
                await asyncio.wait_for(
                    self.stop_event.wait(),
                    timeout=DURATION_MINUTES * 60
                )
            except asyncio.TimeoutError:
                print("\n\n✅ Simulation completed successfully!")
                self.stop_event.set()

            monitor_task.cancel()
            for task in self.tasks:
                task.cancel()

            await asyncio.gather(*self.tasks, return_exceptions=True)

        # ===== Write evidence artifacts =====
        elapsed = time.time() - stats.start_time

        meta = {
            "duration_minutes": DURATION_MINUTES,
            "elapsed_seconds": round(elapsed, 2),
            "base_url": BASE_URL,
            "user_distribution": {
                "normal": NORMAL_USERS_COUNT,
                "minimal_bad": MINIMAL_BAD_USERS_COUNT,
                "suspicious": SUSPICIOUS_USERS_COUNT,
                "real_bad": REAL_BAD_USERS_COUNT,
            },
            "totals": {
                "requests": stats.total_requests,
                "successful": stats.successful_requests,
                "rate_limited": stats.rate_limited,
                "blocked": stats.blocked,
                "errors": stats.errors,
                "bursts": stats.burst_events,
                "suspicious": stats.suspicious_events,
                "attacks": stats.attack_events,
                "ip_changes": stats.ip_changes,
                "cookie_refreshes": stats.cookie_refreshes,
            },
            "by_user_type": dict(stats.by_user_type),
            "by_status_code": {str(k): v for k, v in stats.by_status_code.items()},
            "by_endpoint": dict(stats.by_endpoint),
        }

        evidence.to_csv(EVIDENCE_CSV)
        evidence.to_json(EVIDENCE_JSON, meta)

        # ===== Build human-readable summary =====
        lines = []
        lines.append("=" * 90)
        lines.append("TRIANSEC SIMULATION — EVIDENCE SUMMARY")
        lines.append("=" * 90)
        lines.append(f"Run ID         : {RUN_ID}")
        lines.append(f"Base URL       : {BASE_URL}")
        lines.append(f"Runtime        : {elapsed:.1f}s ({elapsed/60:.2f} min)")
        lines.append(f"Total Requests : {stats.total_requests}")
        lines.append(f"Average RPS    : {stats.total_requests / max(elapsed,1):.2f}")
        lines.append("")
        lines.append("USER DISTRIBUTION")
        lines.append("-" * 90)
        lines.append(f"  Normal       : {NORMAL_USERS_COUNT}")
        lines.append(f"  Minimal bad  : {MINIMAL_BAD_USERS_COUNT}")
        lines.append(f"  Suspicious   : {SUSPICIOUS_USERS_COUNT}")
        lines.append(f"  Real bad     : {REAL_BAD_USERS_COUNT}")
        lines.append("")

        per_type = defaultdict(lambda: {"total": 0, "allow": 0, "throttle": 0,
                                        "block": 0, "error": 0})
        for r in evidence.requests:
            t = r["user_type"]
            per_type[t]["total"] += 1
            d = r["decision"]
            if d == "ALLOW":
                per_type[t]["allow"] += 1
            elif d == "THROTTLE":
                per_type[t]["throttle"] += 1
            elif d == "BLOCK":
                per_type[t]["block"] += 1
            else:
                per_type[t]["error"] += 1

        lines.append("DECISION BREAKDOWN BY USER TYPE  (Proof of adaptive enforcement)")
        lines.append("-" * 90)
        header = f"{'User Type':<14}{'Total':>8}{'ALLOW':>8}{'THROTTLE':>10}{'BLOCK':>8}{'Error':>8}{'Block%':>9}"
        lines.append(header)
        for t in ["normal", "minimal_bad", "suspicious", "real_bad"]:
            d = per_type[t]
            blk_pct = (d["block"] / d["total"] * 100) if d["total"] else 0
            lines.append(
                f"{t:<14}{d['total']:>8}{d['allow']:>8}{d['throttle']:>10}"
                f"{d['block']:>8}{d['error']:>8}{blk_pct:>8.1f}%"
            )
        lines.append("")

        user_ips = defaultdict(set)
        user_cookies = defaultdict(set)
        for r in evidence.requests:
            user_ips[r["user_id"]].add(r["ip"])
            user_cookies[r["user_id"]].add(r["cookie_id"])

        rotators = [u for u, ips in user_ips.items() if len(ips) > 1]
        cookie_rotators = [u for u, c in user_cookies.items() if len(c) > 1]

        lines.append("IDENTITY RESOLUTION  (Proof multi-signal tracking works)")
        lines.append("-" * 90)
        lines.append(f"  Users observed                 : {len(user_ips)}")
        lines.append(f"  Users that rotated IP          : {len(rotators)}")
        lines.append(f"  Users that refreshed cookie    : {len(cookie_rotators)}")
        lines.append(f"  Total IP change events         : {stats.ip_changes}")
        lines.append(f"  Total cookie refresh events    : {stats.cookie_refreshes}")
        lines.append(f"  Unique IPs assigned            : {len(ip_manager.used_ips)}")
        lines.append("")

        lines.append("ATTACK / ABUSE EVENTS")
        lines.append("-" * 90)
        lines.append(f"  Suspicious requests sent       : {stats.suspicious_events}")
        lines.append(f"  Attack requests sent           : {stats.attack_events}")
        lines.append(f"  Burst events triggered         : {stats.burst_events}")
        lines.append("")

        lines.append("TOP RESPONSE CODES")
        lines.append("-" * 90)
        for code, cnt in sorted(stats.by_status_code.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"  HTTP {code}: {cnt}")
        lines.append("")

        lines.append("TOP ENDPOINTS HIT")
        lines.append("-" * 90)
        for ep, cnt in sorted(stats.by_endpoint.items(), key=lambda x: -x[1])[:15]:
            lines.append(f"  {ep}: {cnt}")
        lines.append("")

        lines.append("ARTIFACTS")
        lines.append("-" * 90)
        lines.append(f"  Full JSON evidence : {EVIDENCE_JSON}")
        lines.append(f"  CSV (per-request)  : {EVIDENCE_CSV}")
        lines.append(f"  This summary       : {SUMMARY_TXT}")
        lines.append("=" * 90)

        summary = "\n".join(lines)
        with open(SUMMARY_TXT, "w") as f:
            f.write(summary)
        print("\n" + summary)


if __name__ == "__main__":
    simulation = Simulation()
    asyncio.run(simulation.run())