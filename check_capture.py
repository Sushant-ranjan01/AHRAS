"""
AHRAS — Packet Capture Diagnostic
Run this BEFORE starting the main app to check whether real packet
capture will actually work on this machine.

Usage:  python check_capture.py
"""
import sys, ctypes, os

print("=" * 60)
print("  AHRAS Packet Capture Diagnostic")
print("=" * 60)

# 1. Is scapy importable at all?
try:
    from scapy.all import get_if_list, conf
    print("[OK] scapy is installed and importable.")
except ImportError as e:
    print(f"[FAIL] scapy import failed: {e}")
    print("  -> Run: pip install scapy")
    sys.exit(1)

# 2. Admin / root check
if os.name == "nt":
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    print(f"[{'OK' if is_admin else 'FAIL'}] Running as Administrator: {is_admin}")
    if not is_admin:
        print("  -> Raw packet capture on Windows requires Administrator.")
        print("     Right-click PowerShell/cmd -> 'Run as administrator', then")
        print("     re-run this script and the app from that elevated window.")
else:
    is_root = os.geteuid() == 0
    print(f"[{'OK' if is_root else 'FAIL'}] Running as root: {is_root}")
    if not is_root:
        print("  -> Raw packet capture on Linux/macOS requires root.")
        print("     Try: sudo python check_capture.py")

# 3. List interfaces scapy can see
print("\nInterfaces scapy can see:")
try:
    ifaces = get_if_list()
    if not ifaces:
        print("  [FAIL] No interfaces found. On Windows this almost always")
        print("  means Npcap is not installed. Install it from:")
        print("  https://npcap.com/  (check 'WinPcap API-compatible Mode')")
    else:
        for i, name in enumerate(ifaces):
            marker = " <- scapy default" if name == conf.iface else ""
            print(f"  [{i}] {name}{marker}")
        print(f"\n  Default interface scapy would use: {conf.iface}")
        print("  NOTE: this default is often WRONG when you have many virtual")
        print("  adapters (VPN, VMware/VirtualBox, Bluetooth, Loopback, etc).")
except Exception as e:
    print(f"  [FAIL] Could not list interfaces: {e}")
    print("  -> Npcap is likely missing or not installed correctly.")

# 3b. On Windows, show friendly names + IPs so you can identify the RIGHT one,
# and auto-detect which one is actually carrying your internet traffic.
if os.name == "nt":
    print("\nFriendly interface names (matched to your real internet-facing IP):")
    try:
        import socket as _socket
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        print(f"  Your machine's active internet IP: {local_ip}")
        from scapy.arch.windows import get_windows_if_list
        recommended = None
        for iface in get_windows_if_list():
            ips = iface.get("ips") or []
            match = " <-- USE THIS ONE (matches your active IP)" if local_ip in ips else ""
            if match: recommended = iface.get("name")
            print(f"  - {iface.get('description', iface.get('name'))}: {ips}{match}")
        if recommended:
            print(f"\n  [OK] Recommended NETWORK_INTERFACE value for your .env:")
            print(f"       NETWORK_INTERFACE={recommended}")
            print("  (AHRAS now auto-detects this at startup too, so you likely")
            print("   don't even need to set it manually anymore.)")
        else:
            print("  [WARN] Could not match any adapter to your active IP.")
    except Exception as e:
        print(f"  [FAIL] Could not enumerate friendly interface names: {e}")

# 4. Try an actual 3-second live capture test
test_iface = globals().get('recommended') or None
print(f"\nAttempting a 3-second live capture test on "
      f"{'auto-detected interface: ' + test_iface if test_iface else 'scapy default interface'} "
      f"(needs real traffic)...")
try:
    from scapy.all import sniff
    kw = dict(timeout=3, count=20)
    if test_iface: kw["iface"] = test_iface
    pkts = sniff(**kw)
    print(f"[{'OK' if len(pkts) > 0 else 'WARN'}] Captured {len(pkts)} packet(s) in 3 seconds.")
    if len(pkts) == 0:
        print("  -> Either there's genuinely no traffic on this interface right now,")
        print("     or the wrong interface is selected. Try browsing the web in")
        print("     another window while re-running this script.")
except Exception as e:
    print(f"[FAIL] Live capture test failed: {e}")

print("\nDone.")
