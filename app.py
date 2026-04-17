import os
import base64
import requests
import csv
import io

from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///ioc_data.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")


class IOC(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    tag = db.Column(db.String(50), nullable=False)
    source = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.String(50), nullable=False)

    # VirusTotal fields
    vt_status = db.Column(db.String(50), nullable=True)
    vt_malicious = db.Column(db.Integer, nullable=True)
    vt_suspicious = db.Column(db.Integer, nullable=True)
    vt_harmless = db.Column(db.Integer, nullable=True)
    vt_undetected = db.Column(db.Integer, nullable=True)
    vt_last_analysis_date = db.Column(db.String(50), nullable=True)

    # AbuseIPDB fields
    abuse_status = db.Column(db.String(50), nullable=True)
    abuse_confidence_score = db.Column(db.Integer, nullable=True)
    abuse_country = db.Column(db.String(100), nullable=True)
    abuse_isp = db.Column(db.String(255), nullable=True)
    abuse_domain = db.Column(db.String(255), nullable=True)
    abuse_usage_type = db.Column(db.String(255), nullable=True)
    abuse_total_reports = db.Column(db.Integer, nullable=True)
    abuse_last_reported_at = db.Column(db.String(50), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "value": self.value,
            "type": self.type,
            "tag": self.tag,
            "source": self.source,
            "timestamp": self.timestamp,
            "vt_status": self.vt_status,
            "vt_malicious": self.vt_malicious,
            "vt_suspicious": self.vt_suspicious,
            "vt_harmless": self.vt_harmless,
            "vt_undetected": self.vt_undetected,
            "vt_last_analysis_date": self.vt_last_analysis_date,
        

            "abuse_status": self.abuse_status,
            "abuse_confidence_score": self.abuse_confidence_score,
            "abuse_country": self.abuse_country,
            "abuse_isp": self.abuse_isp,
            "abuse_domain": self.abuse_domain,
            "abuse_usage_type": self.abuse_usage_type,
            "abuse_total_reports": self.abuse_total_reports,
            "abuse_last_reported_at": self.abuse_last_reported_at,
}

with app.app_context():
    db.create_all()


def vt_headers():
    return {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }


def encode_url_for_vt(url_value: str) -> str:
    """
    VirusTotal URL lookups use a URL-safe base64 identifier without '=' padding.
    """
    encoded = base64.urlsafe_b64encode(url_value.encode()).decode()
    return encoded.strip("=")


def get_vt_endpoint(ioc_type: str, ioc_value: str):
    ioc_type = ioc_type.lower().strip()

    if ioc_type == "ip":
        return f"{VT_BASE_URL}/ip_addresses/{ioc_value}"
    elif ioc_type == "domain":
        return f"{VT_BASE_URL}/domains/{ioc_value}"
    elif ioc_type == "hash":
        return f"{VT_BASE_URL}/files/{ioc_value}"
    elif ioc_type == "url":
        url_id = encode_url_for_vt(ioc_value)
        return f"{VT_BASE_URL}/urls/{url_id}"
    else:
        return None


def auto_tag_ioc(ioc: IOC):
    """
    Update IOC tag automatically based on VirusTotal results.
    """
    malicious = ioc.vt_malicious or 0
    suspicious = ioc.vt_suspicious or 0
    harmless = ioc.vt_harmless or 0

    # Simple tagging logic
    if malicious >= 5:
        ioc.tag = "Malware"
    elif malicious >= 1:
        ioc.tag = "Suspicious"
    elif suspicious >= 1:
        ioc.tag = "Suspicious"
    elif malicious == 0 and suspicious == 0 and harmless >= 1:
        ioc.tag = "Benign"


def enrich_ioc_with_vt(ioc: IOC):
    if not VT_API_KEY:
        ioc.vt_status = "API key missing"
        db.session.commit()
        return

    endpoint = get_vt_endpoint(ioc.type, ioc.value)
    if not endpoint:
        ioc.vt_status = "Unsupported IOC type"
        db.session.commit()
        return

    try:
        response = requests.get(endpoint, headers=vt_headers(), timeout=20)

        if response.status_code == 200:
            data = response.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})

            ioc.vt_status = "Enriched"

            if ioc.source:
                if "VT" not in ioc.source:
                    ioc.source = f"{ioc.source}, VT"
            else:
                ioc.source = "VT"

            ioc.vt_malicious = stats.get("malicious", 0)
            ioc.vt_suspicious = stats.get("suspicious", 0)
            ioc.vt_harmless = stats.get("harmless", 0)
            ioc.vt_undetected = stats.get("undetected", 0)

            last_analysis_date = attrs.get("last_analysis_date")
            if last_analysis_date:
                ioc.vt_last_analysis_date = datetime.fromtimestamp(
                    last_analysis_date
                ).strftime("%Y-%m-%d %H:%M:%S")
            else:
                ioc.vt_last_analysis_date = "N/A"

            auto_tag_ioc(ioc)

        elif response.status_code == 404:
            ioc.vt_status = "Not found in VT"

        elif response.status_code == 401:
            ioc.vt_status = "Invalid API key"

        elif response.status_code == 429:
            ioc.vt_status = "Rate limit hit"

        else:
            ioc.vt_status = f"VT error {response.status_code}"

    except requests.RequestException:
        ioc.vt_status = "Request failed"

    db.session.commit()

def abuseipdb_headers():
    return {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }


def enrich_ioc_with_abuseipdb(ioc: IOC):
    if ioc.type.lower() != "ip":
        ioc.abuse_status = "Only valid for IP"
        db.session.commit()
        return

    if not ABUSEIPDB_API_KEY:
        ioc.abuse_status = "API key missing"
        db.session.commit()
        return

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": ioc.value,
        "maxAgeInDays": 90,
        "verbose": "true"
    }

    try:
        response = requests.get(
            url,
            headers=abuseipdb_headers(),
            params=params,
            timeout=20
        )

        if response.status_code == 200:
            data = response.json().get("data", {})

            ioc.abuse_status = "Enriched"

            if ioc.source:
                if "AbuseIPDB" not in ioc.source:
                    ioc.source = f"{ioc.source}, AbuseIPDB"
            else:
                ioc.source = "AbuseIPDB"

            ioc.abuse_confidence_score = data.get("abuseConfidenceScore")
            ioc.abuse_country = data.get("countryCode")
            ioc.abuse_isp = data.get("isp")
            ioc.abuse_domain = data.get("domain")
            ioc.abuse_usage_type = data.get("usageType")
            ioc.abuse_total_reports = data.get("totalReports")
            ioc.abuse_last_reported_at = data.get("lastReportedAt")

            score = ioc.abuse_confidence_score or 0
            if score >= 75:
                ioc.tag = "C2"
            elif score >= 25 and ioc.tag not in ["Malware", "C2"]:
                ioc.tag = "Suspicious"

        elif response.status_code == 401:
            ioc.abuse_status = "Invalid API key"

        elif response.status_code == 422:
            ioc.abuse_status = "Invalid IP format"

        elif response.status_code == 429:
            ioc.abuse_status = "Rate limit hit"

        else:
            ioc.abuse_status = f"AbuseIPDB error {response.status_code}"

    except requests.RequestException:
        ioc.abuse_status = "Request failed"

    db.session.commit()

@app.route("/")
def dashboard():
    search = request.args.get("search", "").strip()
    filter_type = request.args.get("type", "").strip()
    filter_tag = request.args.get("tag", "").strip()
    filter_source = request.args.get("source", "").strip()

    query = IOC.query

    if search:
        query = query.filter(IOC.value.ilike(f"%{search}%"))

    if filter_type:
        query = query.filter(IOC.type == filter_type)

    if filter_tag:
        query = query.filter(IOC.tag == filter_tag)

    if filter_source:
        query = query.filter(IOC.source == filter_source)

    iocs = query.order_by(IOC.id.desc()).all()

    return render_template(
        "index.html",
        iocs=iocs,
        search=search,
        filter_type=filter_type,
        filter_tag=filter_tag,
        filter_source=filter_source
    )


@app.route("/add_ioc", methods=["POST"])
def add_ioc():
    data = request.form

    new_ioc = IOC(
        value=data.get("value"),
        type=data.get("type"),
        tag=data.get("tag"),
        source=data.get("source"),
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    db.session.add(new_ioc)
    db.session.commit()

    # Automatic enrichment pipeline
    enrich_ioc_with_vt(new_ioc)

    if new_ioc.type.lower() == "ip":
        enrich_ioc_with_abuseipdb(new_ioc)

    return redirect(url_for("dashboard"))


@app.route("/enrich_vt/<int:ioc_id>", methods=["POST"])
def enrich_vt(ioc_id):
    ioc = IOC.query.get_or_404(ioc_id)
    enrich_ioc_with_vt(ioc)
    return redirect(url_for("dashboard"))


@app.route("/api/iocs", methods=["GET"])
def get_iocs():
    iocs = IOC.query.order_by(IOC.id.desc()).all()
    return jsonify([ioc.to_dict() for ioc in iocs])

@app.route("/enrich_abuse/<int:ioc_id>", methods=["POST"])
def enrich_abuse(ioc_id):
    ioc = IOC.query.get_or_404(ioc_id)
    enrich_ioc_with_abuseipdb(ioc)
    return redirect(url_for("dashboard"))

@app.route("/delete_ioc/<int:ioc_id>", methods=["POST"])
def delete_ioc(ioc_id):
    ioc = IOC.query.get_or_404(ioc_id)
    db.session.delete(ioc)
    db.session.commit()
    return redirect(url_for("dashboard"))

@app.route("/edit_ioc/<int:ioc_id>", methods=["GET", "POST"])
def edit_ioc(ioc_id):
    ioc = IOC.query.get_or_404(ioc_id)

    if request.method == "POST":
        ioc.value = request.form.get("value")
        ioc.type = request.form.get("type")
        ioc.tag = request.form.get("tag")
        ioc.source = request.form.get("source")

        db.session.commit()
        return redirect(url_for("dashboard"))

    return render_template("edit.html", ioc=ioc)

@app.route("/bulk_upload", methods=["POST"])
def bulk_upload():
    file = request.files.get("file")

    if not file or file.filename == "":
        return redirect(url_for("dashboard"))

    try:
        stream = io.StringIO(file.stream.read().decode("utf-8"))
        reader = csv.DictReader(stream)

        for row in reader:
            value = (row.get("value") or "").strip()
            ioc_type = (row.get("type") or "").strip()
            tag = (row.get("tag") or "").strip()
            source = (row.get("source") or "").strip()

            if not value or not ioc_type or not tag or not source:
                continue

            new_ioc = IOC(
                value=value,
                type=ioc_type,
                tag=tag,
                source=source,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )

            db.session.add(new_ioc)
            db.session.commit()

            # Automatic enrichment pipeline
            enrich_ioc_with_vt(new_ioc)

            if new_ioc.type.lower() == "ip":
                enrich_ioc_with_abuseipdb(new_ioc)

        return redirect(url_for("dashboard"))

    except Exception as e:
        return f"Bulk upload failed: {str(e)}", 400


if __name__ == "__main__":
    app.run(debug=True)