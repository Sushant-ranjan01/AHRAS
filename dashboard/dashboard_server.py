from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from event_management.mongodb_client import MongoDBClient
from analytics.attack_trends import AttackTrends

import socket
import platform
import requests

app = FastAPI()

mongo_client = MongoDBClient()
analyzer = AttackTrends(mongo_client)

# CACHE
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

    data = analyzer.analyze()

    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    os_info = platform.system() + " " + platform.release()

    attackers = sorted(data.get("top_5_attackers", []), key=lambda x: x[1], reverse=True)

    labels = [ip for ip, _ in attackers]
    values = [count for _, count in attackers]

    max_count = max(values) if values else 1

    geo_points = []
    table_rows = ""

    for ip, count in attackers:

        domain = resolve_ip(ip)
        geo = get_geo(ip)

        geo_points.append([geo["lat"], geo["lon"], ip])

        ratio = count / max_count
        risk_score = int(ratio * 100)

        if ratio > 0.7:
            severity = "HIGH"
            badge = "high"
        elif ratio > 0.3:
            severity = "MEDIUM"
            badge = "medium"
        else:
            severity = "LOW"
            badge = "low"

        highlight = "background:#334155;" if count == max_count else ""

        table_rows += f"""
        <tr style="{highlight}" title="IP: {ip} | Domain: {domain}">
            <td>{ip}</td>
            <td class="domain">{domain}</td>
            <td>{geo['country']}</td>
            <td class="num">{count}</td>
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
                font-size:26px;
                color:#38bdf8;
            }}

            .navbar p {{
                font-size:13px;
                color:#94a3b8;
                margin-top:5px;
            }}

            .section {{
                background:#1e293b;
                padding:20px;
                margin:20px;
                border-radius:10px;
            }}

            /* ✅ FIXED TABLE GRID */
            table {{
                width:100%;
                border-collapse:collapse;
                table-layout:fixed;
            }}

            th, td {{
                padding:10px;
                border:1px solid #334155;
                overflow:hidden;
                text-overflow:ellipsis;
                white-space:nowrap;
            }}

            /* ✅ COLUMN WIDTH CONTROL */
            th:nth-child(1), td:nth-child(1) {{ width:15%; }}
            th:nth-child(2), td:nth-child(2) {{ width:30%; }}
            th:nth-child(3), td:nth-child(3) {{ width:15%; }}
            th:nth-child(4), td:nth-child(4) {{ width:10%; }}
            th:nth-child(5), td:nth-child(5) {{ width:10%; }}
            th:nth-child(6), td:nth-child(6) {{ width:10%; }}

            th {{
                color:#94a3b8;
                font-size:12px;
                background:#020617;
                text-transform:uppercase;
            }}

            tr:hover {{
                background:#334155;
            }}

            .num {{
                text-align:right;
            }}

            .domain {{
                color:#cbd5f5;
            }}

            /* BADGES */
            .badge {{
                padding:5px 10px;
                border-radius:12px;
                font-size:12px;
                font-weight:bold;
            }}

            .high {{ background:#ef4444; }}
            .medium {{ background:#f59e0b; color:black; }}
            .low {{ background:#22c55e; }}

            #map {{
                height:300px;
                border-radius:10px;
            }}
        </style>
    </head>

    <body>

        <div class="navbar">
            <h1>AHRAS Security Operations Center</h1>
            <p>Endpoint: {hostname} | IP: {local_ip} | OS: {os_info}</p>
        </div>

        <div class="section">
            <h3>Threat Intelligence</h3>
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
            <h3>Attack Trends</h3>
            <canvas id="chart" style="max-height:250px;"></canvas>
        </div>

        <div class="section">
            <h3>Global Threat Map</h3>
            <div id="map"></div>
        </div>

        <script>

            // 10 min refresh
            setTimeout(() => location.reload(), 600000);

            new Chart(document.getElementById('chart'), {{
                type: 'bar',
                data: {{
                    labels: {labels},
                    datasets: [{{
                        label: 'Attack Volume',
                        data: {values},
                        backgroundColor: '#f97316',
                        barPercentage: 0.5,
                        categoryPercentage: 0.5
                    }}]
                }}
            }});

            var map = L.map('map').setView([20, 0], 2);

            L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png').addTo(map);

            var points = {geo_points};

            points.forEach(p => {{
                if (p[0] !== 0)
                    L.marker([p[0], p[1]])
                        .addTo(map)
                        .bindPopup("IP: " + p[2]);
            }});

        </script>

    </body>
    </html>
    """

    return html