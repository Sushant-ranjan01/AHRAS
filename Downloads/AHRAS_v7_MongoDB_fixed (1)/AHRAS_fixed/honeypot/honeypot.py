"""AHRAS — Honeypot System
Runs fake SSH, FTP, and HTTP services to detect and fingerprint attackers.
Any connection to a honeypot is guaranteed malicious.
"""
import socket
import threading
import time
import logging
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from collections import deque

logger = logging.getLogger("ahras.honeypot")


@dataclass
class HoneypotHit:
    hit_id: str
    service: str        # SSH, FTP, HTTP
    src_ip: str
    src_port: int
    dst_port: int
    data: str           # what the attacker sent
    timestamp: float = field(default_factory=time.time)
    country: str = "Unknown"

    def to_dict(self) -> dict:
        return {
            "hit_id": self.hit_id,
            "service": self.service,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "data": self.data[:500],  # truncate
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp)),
            "country": self.country,
        }


class _FakeSSH:
    BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

    def __init__(self, port: int, on_hit):
        self.port = port
        self.on_hit = on_hit
        self._server: Optional[socket.socket] = None
        self._running = False

    def start(self):
        try:
            self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server.bind(("0.0.0.0", self.port))
            self._server.listen(5)
            self._server.settimeout(1.0)
            self._running = True
            threading.Thread(target=self._accept_loop, daemon=True).start()
            logger.info(f"Honeypot SSH started on :{self.port}")
            return True
        except Exception as e:
            logger.warning(f"Honeypot SSH failed to start on :{self.port}: {e}")
            return False

    def stop(self):
        self._running = False
        if self._server:
            try:
                self._server.close()
            except Exception:
                pass

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._server.accept()
                threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _handle(self, conn: socket.socket, addr):
        src_ip, src_port = addr
        try:
            conn.settimeout(5.0)
            conn.send(self.BANNER)
            try:
                data = conn.recv(256).decode("utf-8", errors="replace").strip()
            except Exception:
                data = "<no data>"
            self.on_hit(HoneypotHit(
                hit_id=str(uuid.uuid4())[:8],
                service="SSH",
                src_ip=src_ip,
                src_port=src_port,
                dst_port=self.port,
                data=data,
            ))
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass


class _FakeFTP:
    BANNER = b"220 FTP server ready\r\n"
    PROMPT = b"331 Password required for user\r\n"

    def __init__(self, port: int, on_hit):
        self.port = port
        self.on_hit = on_hit
        self._server: Optional[socket.socket] = None
        self._running = False

    def start(self):
        try:
            self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server.bind(("0.0.0.0", self.port))
            self._server.listen(5)
            self._server.settimeout(1.0)
            self._running = True
            threading.Thread(target=self._accept_loop, daemon=True).start()
            logger.info(f"Honeypot FTP started on :{self.port}")
            return True
        except Exception as e:
            logger.warning(f"Honeypot FTP failed to start on :{self.port}: {e}")
            return False

    def stop(self):
        self._running = False
        if self._server:
            try:
                self._server.close()
            except Exception:
                pass

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._server.accept()
                threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _handle(self, conn: socket.socket, addr):
        src_ip, src_port = addr
        captured = []
        try:
            conn.settimeout(8.0)
            conn.send(self.BANNER)
            for _ in range(4):
                try:
                    data = conn.recv(256).decode("utf-8", errors="replace").strip()
                    if not data:
                        break
                    captured.append(data)
                    if data.upper().startswith("USER"):
                        conn.send(self.PROMPT)
                    elif data.upper().startswith("PASS"):
                        conn.send(b"530 Login incorrect\r\n")
                        break
                    else:
                        conn.send(b"500 Unknown command\r\n")
                except Exception:
                    break
            self.on_hit(HoneypotHit(
                hit_id=str(uuid.uuid4())[:8],
                service="FTP",
                src_ip=src_ip,
                src_port=src_port,
                dst_port=self.port,
                data=" | ".join(captured) or "<empty>",
            ))
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass


class _FakeHTTP:
    RESPONSE = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.54 (Ubuntu)\r\n"
        b"Content-Type: text/html\r\n"
        b"Content-Length: 45\r\n"
        b"\r\n"
        b"<html><body><h1>It works!</h1></body></html>"
    )

    def __init__(self, port: int, on_hit):
        self.port = port
        self.on_hit = on_hit
        self._server: Optional[socket.socket] = None
        self._running = False

    def start(self):
        try:
            self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server.bind(("0.0.0.0", self.port))
            self._server.listen(10)
            self._server.settimeout(1.0)
            self._running = True
            threading.Thread(target=self._accept_loop, daemon=True).start()
            logger.info(f"Honeypot HTTP started on :{self.port}")
            return True
        except Exception as e:
            logger.warning(f"Honeypot HTTP failed to start on :{self.port}: {e}")
            return False

    def stop(self):
        self._running = False
        if self._server:
            try:
                self._server.close()
            except Exception:
                pass

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._server.accept()
                threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _handle(self, conn: socket.socket, addr):
        src_ip, src_port = addr
        try:
            conn.settimeout(5.0)
            data = conn.recv(4096).decode("utf-8", errors="replace")
            # Parse first line
            first_line = data.split("\n")[0].strip() if data else "<empty>"
            conn.send(self.RESPONSE)
            self.on_hit(HoneypotHit(
                hit_id=str(uuid.uuid4())[:8],
                service="HTTP",
                src_ip=src_ip,
                src_port=src_port,
                dst_port=self.port,
                data=first_line,
            ))
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass


class HoneypotManager:
    """Manages all honeypot services and collects hits."""

    def __init__(self, ssh_port: int = 2222, ftp_port: int = 2121, http_port: int = 8080):
        self._ssh_port = ssh_port
        self._ftp_port = ftp_port
        self._http_port = http_port
        self._hits: deque = deque(maxlen=1000)
        self._lock = threading.Lock()
        self._services: Dict[str, any] = {}
        self._running = False
        self._total_hits = 0
        self._attacker_ips: Dict[str, int] = {}
        self._on_hit_callbacks = []

    def on_hit(self, callback):
        """Register a callback for honeypot hits (receives HoneypotHit)."""
        self._on_hit_callbacks.append(callback)

    def _record_hit(self, hit: HoneypotHit):
        with self._lock:
            self._hits.appendleft(hit)
            self._total_hits += 1
            self._attacker_ips[hit.src_ip] = self._attacker_ips.get(hit.src_ip, 0) + 1
        logger.warning(f"HONEYPOT HIT: {hit.service} from {hit.src_ip}:{hit.src_port} — {hit.data[:80]}")
        for cb in self._on_hit_callbacks:
            try:
                cb(hit)
            except Exception as e:
                logger.error(f"Honeypot callback error: {e}")

    def start(self) -> dict:
        results = {}
        self._services["ssh"] = _FakeSSH(self._ssh_port, self._record_hit)
        self._services["ftp"] = _FakeFTP(self._ftp_port, self._record_hit)
        self._services["http"] = _FakeHTTP(self._http_port, self._record_hit)

        for name, svc in self._services.items():
            ok = svc.start()
            results[name] = "running" if ok else "failed"

        self._running = any(v == "running" for v in results.values())
        return results

    def stop(self):
        for svc in self._services.values():
            svc.stop()
        self._running = False

    def recent_hits(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return [h.to_dict() for h in list(self._hits)[:limit]]

    def stats(self) -> dict:
        with self._lock:
            top_attackers = sorted(self._attacker_ips.items(), key=lambda x: x[1], reverse=True)[:10]
            service_counts: Dict[str, int] = {}
            for h in self._hits:
                service_counts[h.service] = service_counts.get(h.service, 0) + 1
            return {
                "running": self._running,
                "total_hits": self._total_hits,
                "unique_attackers": len(self._attacker_ips),
                "top_attackers": [{"ip": ip, "hits": n} for ip, n in top_attackers],
                "by_service": service_counts,
                "services": {
                    "ssh": f":{self._ssh_port}",
                    "ftp": f":{self._ftp_port}",
                    "http": f":{self._http_port}",
                },
            }
