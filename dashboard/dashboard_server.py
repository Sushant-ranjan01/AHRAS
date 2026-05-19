from fastapi import FastAPI, Request

from fastapi.responses import JSONResponse

from fastapi.templating import Jinja2Templates

from fastapi.staticfiles import StaticFiles

from event_management.mongodb_client import MongoDBClient

import socket

import platform

import requests


app = FastAPI()

mongo_client = MongoDBClient()

templates = Jinja2Templates(directory="dashboard/templates")

app.mount(
    "/static",
    StaticFiles(directory="dashboard/static"),
    name="static"
)

geo_cache = {}

dns_cache = {}


# --------------------------------
# DNS RESOLUTION
# --------------------------------
def resolve_ip(ip):

    if ip in dns_cache:
        return dns_cache[ip]

    try:

        name = socket.gethostbyaddr(ip)[0]

    except:

        name = "Unknown"

    dns_cache[ip] = name

    return name


# --------------------------------
# GEO LOCATION
# --------------------------------
def get_geo(ip):

    if ip in geo_cache:
        return geo_cache[ip]

    try:

        res = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=2
        ).json()

        geo = {
            "country": res.get("country", "Unknown")
        }

    except:

        geo = {
            "country": "Unknown"
        }

    geo_cache[ip] = geo

    return geo


# --------------------------------
# DASHBOARD PAGE
# --------------------------------
@app.get("/dashboard")
def dashboard(request: Request):

    hostname = socket.gethostname()

    local_ip = socket.gethostbyname(hostname)

    os_info = platform.system() + " " + platform.release()

    return templates.TemplateResponse(

        request,

        "dashboard.html",

        {
            "hostname": hostname,

            "local_ip": local_ip,

            "os_info": os_info
        }
    )


# --------------------------------
# EVENTS API
# --------------------------------
@app.get("/api/events")
def api_events():

    events = mongo_client.get_all_events(limit=20)

    clean = []

    for event in events:

        ip = event.get("source_ip", "unknown")

        dns = resolve_ip(ip)

        geo = get_geo(ip)

        clean.append({

            "timestamp":
                event.get("timestamp", ""),

            "source_ip":
                ip,

            "dns":
                dns,

            "country":
                geo.get("country", "Unknown"),

            "protocol":
                event.get("protocol", 0),

            "risk_score":
                event.get("risk_score", 0),

            "threat_level":
                event.get("threat_level", "LOW"),

            "packet_count":
                event.get("packet_count", 0),

            "attack_types":
                event.get("matched_rules", [])
        })

    return JSONResponse(content=clean)


# --------------------------------
# STATS API
# --------------------------------
@app.get("/api/stats")
def api_stats():

    events = mongo_client.get_all_events(limit=100)

    total = len(events)

    high = 0

    protocols = {

        "TCP": 0,

        "UDP": 0,

        "ICMP": 0,

        "OTHER": 0
    }

    for e in events:

        if e.get("threat_level") in [

            "HIGH",
            "CRITICAL"
        ]:

            high += 1

        proto = e.get("protocol", 0)

        if proto == 6:

            protocols["TCP"] += 1

        elif proto == 17:

            protocols["UDP"] += 1

        elif proto == 1:

            protocols["ICMP"] += 1

        else:

            protocols["OTHER"] += 1

    return {

        "total_events": total,

        "high_alerts": high,

        "protocols": protocols
    }