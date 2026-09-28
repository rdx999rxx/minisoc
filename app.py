from flask import Flask, redirect, render_template, url_for

from database import get_alerts, init_db
from detector import analyze
from parser import parse_file


app = Flask(__name__)


@app.route("/")
def dashboard():
    alerts = get_alerts()
    return render_template("index.html", alerts=alerts)


@app.route("/ingest")
def ingest():
    log_file = "sample_logs/security.log"

    events = parse_file(log_file)
    analyze(events)

    return redirect(url_for("dashboard"))


if __name__ == "__main__":
    init_db()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
    )
