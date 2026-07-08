import os
from datetime import datetime
from flask import Flask, render_template, request, redirect
from generators.apache_generator import  apache_generator
from generators.auth_generator import  auth_generator
from generators.windows_generator import  windows_generator
from src.database.database import (
    create_database,
    get_event, get_alert_count_by_status, get_all_events, get_events_for_alert,
    get_alert, update_alert_status, get_case, get_cases, get_notes,
    get_all_alerts, get_all_cases,
    clear_events, clear_alerts, clear_cases, clear_notes
    )
from src.investigation.cases import open_case, alter_case_status
from src.investigation.notes import add_investigation_note
from src.investigation.verdicts import set_verdict
from src.pipeline import process_logs, ingest_logs, run_detections

app = Flask(__name__)

LOG_DIR = "logs"

ALLOWED = {
    "auth.log",
    "apache.log",
    "windows.log"
}

@app.route("/generate", methods=["POST"])
def generate():

    apache_generator()
    auth_generator()
    windows_generator()

    process_logs()

    return redirect("/")

@app.route("/upload", methods=["POST"])
def upload_logs():

    files = request.files.getlist("logs")

    for file in files:

        if file.filename == "":
            continue

        if file.filename not in ALLOWED:
            continue

        path = os.path.join(LOG_DIR, file.filename)
        file.save(path)

    return redirect("/")

@app.route("/process", methods=["POST"])
def process():

    ingest_logs()

    return redirect("/")

@app.route("/detect", methods=["POST"])
def detections():

    run_detections()

    return redirect("/")

@app.route("/clear", methods=["POST"])
def clear():
    clear_notes()
    clear_cases()
    clear_alerts()
    clear_events()
    return redirect("/")

_TREND_HOURS = 6


def _parse_ts(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        pass
    try:
        return datetime.strptime(ts, "%b %d %H:%M:%S").replace(year=datetime.now().year)
    except ValueError:
        return None


def _hourly_trend(items, ts_key, hours=_TREND_HOURS):
    now = datetime.now()
    buckets = [0] * hours
    for item in items:
        ts = _parse_ts(item[ts_key])
        if ts is None:
            continue
        age_hours = (now - ts).total_seconds() / 3600
        if 0 <= age_hours < hours:
            idx = hours - 1 - int(age_hours)
            buckets[idx] += 1
    delta = buckets[-1] - buckets[0]
    return {"points": _sparkline_points(buckets), "delta": delta}


def _hourly_unique_ip_trend(events, hours=_TREND_HOURS):
    now = datetime.now()
    buckets = [set() for _ in range(hours)]
    for e in events:
        ip = e["source_ip"]
        if not ip:
            continue
        ts = _parse_ts(e["timestamp"])
        if ts is None:
            continue
        age_hours = (now - ts).total_seconds() / 3600
        if 0 <= age_hours < hours:
            idx = hours - 1 - int(age_hours)
            buckets[idx].add(ip)
    counts = [len(b) for b in buckets]
    delta = counts[-1] - counts[0]
    return {"points": _sparkline_points(counts), "delta": delta}


def _sparkline_points(counts, width=100, height=24):
    if not counts:
        return f"0,{height} {width},{height}"
    max_c = max(counts) or 1
    n = len(counts)
    step = width / (n - 1) if n > 1 else width
    pts = []
    for i, c in enumerate(counts):
        x = round(i * step, 1)
        y = round(height - (c / max_c) * height, 1)
        pts.append(f"{x},{y}")
    return " ".join(pts)


SEVERITY_COLORS = {
    "CRITICAL": "var(--danger)",
    "HIGH": "var(--warning)",
    "MEDIUM": "var(--info)",
    "LOW": "var(--text-faint)",
}

TYPE_PALETTE = [
    "var(--info)", "var(--success)", "var(--warning)",
    "var(--danger)", "var(--accent-purple)", "var(--accent-pink)",
    "var(--text-faint)",
]


def _chart_segments(counts, palette):
    total = sum(counts.values())
    segments = []
    cum = 0.0
    for i, (label, count) in enumerate(counts.items()):
        pct = (count / total * 100) if total else 0
        color = palette[i % len(palette)]
        segments.append({
            "label": label,
            "count": count,
            "pct": round(pct, 1),
            "color": color,
            "start": round(cum, 2),
            "end": round(cum + pct, 2),
        })
        cum += pct
    return segments, total


def _conic_gradient(segments, total):
    if not total:
        return "var(--surface-2) 0% 100%"
    return ", ".join(f"{s['color']} {s['start']}% {s['end']}%" for s in segments)


@app.route("/")
def dashboard():

    alerts = get_all_alerts()
    events = get_all_events()

    total_alerts = len(alerts)
    open_alerts = get_alert_count_by_status("NEW")[0][0]
    investigating_alerts = get_alert_count_by_status("INVESTIGATING")[0][0]
    closed_alerts = get_alert_count_by_status("CLOSED")[0][0]

    source_ips = [a["source_ip"] for a in events if a["source_ip"]]
    ip_counts = {}
    for ip in source_ips:
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    unique_ips = len(ip_counts)

    severity_map = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        sev = (a["severity"] or "UNKNOWN").upper()
        if sev in severity_map:
            severity_map[sev] += 1

    type_counts = {}
    for e in events:
        t = e["event_type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    severity_segments, severity_total = _chart_segments(
        severity_map, list(SEVERITY_COLORS.values())
    )
    severity_gradient = _conic_gradient(severity_segments, severity_total)
    type_segments, type_total = _chart_segments(type_counts, TYPE_PALETTE)
    type_gradient = _conic_gradient(type_segments, type_total)

    log_sources = []
    online_count = 0
    for filename in sorted(ALLOWED):
        path = os.path.join(LOG_DIR, filename)
        if os.path.exists(path):
            stat = os.stat(path)
            log_sources.append({
                "name": filename,
                "status": "Active",
                "size_kb": round(stat.st_size / 1024, 1),
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%H:%M:%S"),
            })
            online_count += 1
        else:
            log_sources.append({
                "name": filename,
                "status": "Missing",
                "size_kb": 0,
                "modified": "—",
            })

    timestamps = [e["timestamp"] for e in events if e["timestamp"]]
    last_ingest = max(timestamps) if timestamps else None

    trends = {
        "total_alerts": _hourly_trend(alerts, "created_at"),
        "unique_ips": _hourly_unique_ip_trend(events),
    }

    return render_template(
        "dashboard.html",
        events=events,
        alerts=alerts,
        total_alerts=total_alerts,
        open_alerts=open_alerts,
        investigating_alerts=investigating_alerts,
        closed_alerts=closed_alerts,
        unique_ips=unique_ips,
        top_ips=top_ips,
        trends=trends,
        severity_segments=severity_segments,
        severity_total=severity_total,
        severity_gradient=severity_gradient,
        type_segments=type_segments,
        type_total=type_total,
        type_gradient=type_gradient,
        log_sources=log_sources,
        online_count=online_count,
        total_sources=len(ALLOWED),
        total_events=len(events),
        last_ingest=last_ingest,
    )

@app.route("/events")
def event_page():
    events = get_all_events()
    return render_template("events.html", events=events)

@app.route("/events/<int:event_id>")
def event_details(event_id):
    event = get_event(event_id)
    return render_template("event_details.html", event=event)

@app.route("/alerts")
def alerts_page():
    alerts = get_all_alerts()
    return render_template("alerts.html", alerts=alerts)

@app.route("/alerts/<int:alert_id>")
def alert_details(alert_id):
    alert = get_alert(alert_id)
    events = get_events_for_alert(alert_id)
    cases = get_cases(alert_id)
    case = cases[0] if cases else None
    return render_template("alert_details.html", alert=alert, events=events, case=case)

@app.route("/alerts/<int:alert_id>/status", methods=["POST"])
def alert_status(alert_id):
    status = request.form.get("status")
    if status in ("NEW", "INVESTIGATING", "ESCALATED", "CLOSED"):
        update_alert_status(alert_id, status)

    return redirect(f"/alerts/{alert_id}")

@app.route("/alerts/<int:alert_id>/open_case", methods=["POST"])
def case_open(alert_id):
    case_id = open_case(alert_id)
    return redirect(f"/cases/{case_id}")

@app.route("/cases")
def cases_page():
    cases = get_all_cases()
    return render_template("cases.html", cases=cases)

@app.route("/cases/<int:case_id>")
def case_details(case_id):
    case = get_case(case_id)
    notes = get_notes(case_id)
    return render_template("case_details.html", case=case, notes=notes)

@app.route("/cases/<int:case_id>/status", methods=["POST"])
def case_status(case_id):
    status = request.form.get('status')
    case_data = get_case(case_id)
    alert_id = case_data["alert_id"] if case_data else None
    alter_case_status(case_id, status, alert_id)
    return redirect(f"/cases/{case_id}")

@app.route("/cases/<int:case_id>/verdict", methods=["POST"])
def case_verdict(case_id):
    verdict = request.form.get('verdict')
    set_verdict(case_id, verdict)

    return redirect(f"/cases/{case_id}")

@app.route("/cases/<int:case_id>/note", methods=["POST"])
def case_note(case_id):
    note = request.form.get('note')
    add_investigation_note(case_id, note)
    return redirect(f"/cases/{case_id}")


@app.route("/search")
def search():
    ip = request.args.get("ip", "").strip()
    title = request.args.get("title", "").strip()
    searched = ip or title

    results = []
    if searched:
        all_alerts = get_all_alerts()
        for a in all_alerts:
            ip_match = ip and a["source_ip"] and ip.lower() in a["source_ip"].lower()
            title_match = title and a["title"] and title.lower() in a["title"].lower()
            if ip_match or title_match:
                results.append(a)

    return render_template("search.html", results=results, searched=searched, ip=ip, title=title)


if __name__ == "__main__":
    create_database()
    app.run(debug=True)
