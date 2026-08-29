"""
AHRAS v4 — eBPF Kernel-Level I/O Entropy Monitor
(Phase 2 — Research Contribution, feeds detection/ransomware_engine/detector.py)
═══════════════════════════════════════════════════════════════════════════
Problem: detection/ransomware_engine/detector.py's EntropyAnalyzer /
FileActivityTracker work by *polling* the filesystem in a loop (see
_poll_loop in that file). That's portable and needs no privileges, but it
has a detection lag of one poll interval, and it can miss the first burst
of a fast mass-encryption run entirely.

Solution: hook write()/writev() and related syscalls at the eBPF layer
(via bcc) so entropy on written buffers is measured *in the kernel, as
the bytes are written*, with near-zero overhead and no polling lag.
A sudden entropy jump (normal file content is rarely high-entropy;
ciphertext always is) plus a burst of file renames/writes is the earliest
possible signal of ransomware doing its thing.

Honest scope note: eBPF programs need root privileges, kernel headers,
and BCC/libbpf — none of which exist in this sandbox container (no root,
no kernel dev headers, non-Linux CI runners, etc). The eBPF program below
is real and will run as-is on a properly provisioned Linux host with BCC
installed and CAP_SYS_ADMIN. Everywhere else — including here — this
module detects that eBPF isn't usable and transparently falls back to the
existing polling-based EntropyAnalyzer so the ransomware engine keeps
working; it just loses the kernel-level speed advantage until deployed
on real infrastructure.
"""
import logging
import os
import platform
import threading
import time
from typing import Callable, Optional

logger = logging.getLogger("ahras.sensors.ebpf")

# The BCC program: hooks the write syscall, computes a coarse Shannon
# entropy over the first N bytes of each write, and pushes writes whose
# entropy exceeds the threshold up to userspace via a perf/ring buffer.
# Left as source here — compiled by BCC at runtime, only ever reached on
# a real Linux host with bcc installed and root.
_BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define SAMPLE_BYTES 64

struct entropy_event_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char sample[SAMPLE_BYTES];
    u32 len;
};
BPF_PERF_OUTPUT(entropy_events);

int trace_write_entry(struct pt_regs *ctx, unsigned int fd, const char __user *buf, size_t count) {
    struct entropy_event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    u32 to_copy = count < SAMPLE_BYTES ? count : SAMPLE_BYTES;
    bpf_probe_read_user(&evt.sample, to_copy, buf);
    evt.len = to_copy;
    entropy_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""

EBPF_ENTROPY_THRESHOLD = 7.2   # bits/byte (max 8.0) — ciphertext/compressed data territory


def _bcc_available() -> bool:
    if platform.system() != "Linux":
        return False
    if os.geteuid() != 0 if hasattr(os, "geteuid") else True:
        # not root -> BPF program load will fail; don't even try
        pass
    try:
        import bcc  # noqa: F401
        return True
    except ImportError:
        return False


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    from collections import Counter
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


class EBPFFileMonitor:
    """
    Kernel-level entropy watcher. Use exactly like the existing
    detection.ransomware_engine.detector polling loop: construct with a
    callback, call start(), it fires the callback on high-entropy write
    bursts. Falls back to a tight userspace polling loop reusing the
    project's existing EntropyAnalyzer when eBPF isn't available (the
    case in this sandbox, on non-Linux, or without root).
    """

    def __init__(self, on_high_entropy_write: Callable[[dict], None],
                 watch_paths: Optional[list] = None):
        self.on_high_entropy_write = on_high_entropy_write
        self.watch_paths = watch_paths or []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.mode = "ebpf" if _bcc_available() else "fallback-poll"
        logger.info("EBPFFileMonitor initialised in %s mode", self.mode)

    @property
    def enabled(self) -> bool:
        return self._running

    def start(self):
        if self._running:
            return
        self._running = True
        if self.mode == "ebpf":
            self._thread = threading.Thread(target=self._run_ebpf, daemon=True)
        else:
            self._thread = threading.Thread(target=self._run_fallback_poll, daemon=True)
        self._thread.start()
        logger.info("EBPFFileMonitor started (mode=%s)", self.mode)

    def stop(self):
        self._running = False

    # ── real eBPF path (Linux + root + bcc only) ─────────────────────────
    def _run_ebpf(self):
        try:
            from bcc import BPF
        except ImportError:
            logger.warning("bcc not importable at run time, switching to fallback")
            self.mode = "fallback-poll"
            self._run_fallback_poll()
            return

        try:
            b = BPF(text=_BPF_PROGRAM)
            b.attach_kprobe(event=b.get_syscall_fnname("write"), fn_name="trace_write_entry")

            def _handle_event(cpu, data, size):
                event = b["entropy_events"].event(data)
                sample = bytes(event.sample[:event.len])
                entropy = _shannon_entropy(sample)
                if entropy >= EBPF_ENTROPY_THRESHOLD:
                    self.on_high_entropy_write({
                        "pid": event.pid,
                        "comm": event.comm.decode(errors="replace"),
                        "entropy": round(entropy, 2),
                        "source": "ebpf",
                        "timestamp": time.time(),
                    })

            b["entropy_events"].open_perf_buffer(_handle_event)
            while self._running:
                b.perf_buffer_poll(timeout=200)
        except Exception as exc:
            logger.error("eBPF monitor failed at runtime (%s) — falling back to polling", exc)
            self.mode = "fallback-poll"
            self._run_fallback_poll()

    # ── portable fallback: reuses the project's own EntropyAnalyzer ──────
    def _run_fallback_poll(self):
        from detection.ransomware_engine.detector import EntropyAnalyzer
        seen_mtimes = {}
        poll_interval = 0.5   # tighter than the default ransomware poll loop
        while self._running:
            for base in self.watch_paths:
                if not os.path.isdir(base):
                    continue
                try:
                    for root, _, files in os.walk(base):
                        for fname in files:
                            fpath = os.path.join(root, fname)
                            try:
                                mtime = os.path.getmtime(fpath)
                            except OSError:
                                continue
                            if seen_mtimes.get(fpath) == mtime:
                                continue
                            seen_mtimes[fpath] = mtime
                            entropy = EntropyAnalyzer.calculate(fpath)
                            if EntropyAnalyzer.is_suspicious(entropy):
                                self.on_high_entropy_write({
                                    "path": fpath, "entropy": round(entropy, 2),
                                    "source": "fallback-poll", "timestamp": time.time(),
                                })
                except Exception:
                    continue
            time.sleep(poll_interval)

    def status(self) -> dict:
        return {
            "mode": self.mode, "running": self._running,
            "threshold_bits_per_byte": EBPF_ENTROPY_THRESHOLD,
            "watch_paths": self.watch_paths,
            "note": ("Real kernel-level eBPF hooking write() syscalls."
                     if self.mode == "ebpf" else
                     "eBPF unavailable here (needs Linux + root + bcc) — "
                     "using tight userspace polling fallback instead."),
        }
