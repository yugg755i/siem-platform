import os
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

@app.route("/")
def dashboard():

    alerts = get_all_alerts()
    events = get_all_events()

    total_alerts = len(alerts)
    open_alerts = get_alert_count_by_status("NEW")[0][0]
    investigating_alerts = get_alert_count_by_status("INVESTIGATING")[0][0]
    closed_alerts = get_alert_count_by_status("CLOSED")[0][0]

    source_ips = [a["source_ip"] for a in alerts if a["source_ip"]]
    ip_counts = {}
    for ip in source_ips:
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    unique_ips = len(ip_counts)

    severity_counts = {}
    for a in alerts:
        sev = a["severity"] or "UNKNOWN"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

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
        severity_counts=severity_counts,
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
    return render_template("alert_details.html", alert=alert, events=events, cases=cases)

@app.route("/alerts/<int:alert_id>/status", methods=["POST"])
def status(alert_id):
    status = request.form.get("status")
    if status in ("NEW", "INVESTIGATING", "ESCALATED", "CLOSED"):
        update_alert_status(alert_id, status)

    return redirect(f"/alerts/{alert_id}")

@app.route("/cases")
def cases_page():
    cases = get_all_cases()
    return render_template("cases.html", cases=cases)

@app.route("/cases/<int:case_id>")
def case_details(case_id):
    case = get_case(case_id)
    notes = get_notes(case_id)
    return render_template("case_details.html", case=case, notes=notes)

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
