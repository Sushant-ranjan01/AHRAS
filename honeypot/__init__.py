"""Decoy SSH/FTP/HTTP services that lure and log attacker activity."""
from .honeypot import HoneypotManager
__all__ = ["HoneypotManager"]
