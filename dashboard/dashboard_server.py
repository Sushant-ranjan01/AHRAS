from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from event_management.mongodb_client import MongoDBClient

import socket
import platform
import requests
from datetime import datetime

app = FastAPI()
mongo_client = MongoDBClient()

geo_cache = {}
dns_cache = {}


def resolve_ip(ip):
    if ip in dns_cache:
        return dns_cache[ip]
    try:
        name = socket.gethostbyaddr(ip)[0]
    except:
        name = "Unknown"
    dns_cache[ip] = name
    return name


def get_geo(ip):
    if ip in geo_cache:
        return geo_cache[ip]
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        geo = {
            "lat": res.get("lat", 0),
            "lon": res.get("lon", 0),
            "country": res.get("country", "Unknown")
        }
    except:
        geo = {"lat": 0, "lon": 0, "country": "Unknown"}

    geo_cache[ip] = geo
    return geo


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():

    events = mongo_client.get_all_events()

    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    os_info = platform.system() + " " + platform.release()

    # 🔥 REAL AGGREGATION
    ip_data = {}

    for event in events:
        ip = event.get("source_ip")
        if not ip:
            continue

        risk = event.get("risk_score", 0)
        threat = event.get("threat_level", "LOW")
        timestamp = event.get("timestamp")

        if ip not in ip_data:
            ip_data[ip] = {
                "count": 0,
                "max_risk": 0,
                "total_risk": 0,
                "latest_threat": threat,
                "last_seen": timestamp
            }

        ip_data[ip]["count"] += 1
        ip_data[ip]["total_risk"] += risk
        ip_data[ip]["max_risk"] = max(ip_data[ip]["max_risk"], risk)

        if timestamp:
            ip_data[ip]["last_seen"] = timestamp
            ip_data[ip]["latest_threat"] = threat

    # compute averages
    for ip in ip_data:
        data = ip_data[ip]
        data["avg_risk"] = data["total_risk"] / data["count"]

    # 🔥 SORT BY REAL RISK (NOT COUNT)
    attackers = sorted(
        ip_data.items(),
        key=lambda x: x[1]["max_risk"],
        reverse=True
    )[:5]

    labels = [ip for ip, _ in attackers]
    values = [data["max_risk"] for _, data in attackers]

    geo_points = []
    table_rows = ""

    for ip, data in attackers:

        domain = resolve_ip(ip)
        geo = get_geo(ip)

        geo_points.append([geo["lat"], geo["lon"], ip])

        severity = data["latest_threat"]
        risk_score = int(data["max_risk"])

        if severity == "CRITICAL":
            badge = "high"
        elif severity == "HIGH":
            badge = "high"
        elif severity == "MEDIUM":
            badge = "medium"
        else:
            badge = "low"

        table_rows += f"""
        <tr>
            <td>{ip}</td>
            <td class="domain">{domain}</td>
            <td>{geo['country']}</td>
            <td class="num">{data['count']}</td>
            <td class="num">{risk_score}</td>
            <td><span class="badge {badge}">{severity}</span></td>
        </tr>
        """

    html = f"""
    <html>
    <head>
        <title>AHRAS SOC</title>

        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css" />
        <script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>

        <style>
            body {{
                margin:0;
                font-family:Segoe UI;
                background:#0b1220;
                color:white;
            }}

            .navbar {{
                background:#020617;
                padding:20px;
                text-align:center;
            }}

            .navbar h1 {{
                margin:0;
                font-size:28px;
                color:#38bdf8;
            }}

            .section {{
                background:#1e293b;
                padding:20px;
                margin:20px;
                border-radius:10px;
            }}

            table {{
                width:100%;
                border-collapse:collapse;
            }}

            th, td {{
                padding:10px;
                border:1px solid #334155;
            }}

            th {{
                background:#020617;
                color:#94a3b8;
            }}

            .badge {{
                padding:5px 10px;
                border-radius:12px;
                font-size:12px;
                font-weight:bold;
            }}

            .high {{ background:#ef4444; }}
            .medium {{ background:#f59e0b; color:black; }}
            .low {{ background:#22c55e; }}

            #map {{ height:300px; }}
        </style>
    </head>

    <body>

        <div class="navbar">
            <h1>AHRAS Security Operations Center</h1>
            <p>{hostname} | {local_ip} | {os_info}</p>
        </div>

        <div class="section">
            <h3>Threat Intelligence (Risk-Based)</h3>
            <table>
                <tr>
                    <th>IP</th>
                    <th>Domain</th>
                    <th>Country</th>
                    <th>Events</th>
                    <th>Risk Score</th>
                    <th>Severity</th>
                </tr>
                {table_rows}
            </table>
        </div>

        <div class="section">
            <h3>Top Risk Distribution</h3>
            <canvas id="chart"></canvas>
        </div>

        <div class="section">
            <h3>Global Threat Map</h3>
            <div id="map"></div>
        </div>

        <script>
            new Chart(document.getElementById('chart'), {{
                type: 'bar',
                data: {{
                    labels: {labels},
                    datasets: [{{
                        label: 'Max Risk Score',
                        data: {values}
                    }}]
                }}
            }});

            var map = L.map('map').setView([20, 0], 2);

            L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png').addTo(map);

            var points = {geo_points};

            points.forEach(p => {{
                if (p[0] !== 0)
                    L.marker([p[0], p[1]]).addTo(map)
                        .bindPopup("IP: " + p[2]);
            }});
        </script>

    </body>
    </html>
    """

    return html