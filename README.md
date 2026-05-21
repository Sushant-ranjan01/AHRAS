Step 9 — Run everything
Open four terminals (or use tmux):
bash# Terminal 1 — Normalizer (start this first)
cd ahras && source venv/bin/activate
python -m normalizer.ocsf_normalizer

# Terminal 2 — Network sniffer (needs root for raw packets)
cd ahras && source venv/bin/activate
sudo python -m sensors.packet_sniffer

# Terminal 3 — Host agent (needs root for full process visibility)
cd ahras && source venv/bin/activate
sudo python -m sensors.host_agent

# Terminal 4 — Cloud adapter (synthetic events)
cd ahras && source venv/bin/activate
python -m sensors.cloud_adapter
