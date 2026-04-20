import os
import base64
import requests
import csv
import io
import re

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from datetime import datetime
from sqlalchemy import inspect, text

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-this-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///ioc_data.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

DEFAULT_ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
DEFAULT_ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123!")

NETWORK_ZONES = [
    "Corporate IT",
    "DMZ",
    "OT Level 2",
    "OT Level 1",
    "Field Device",
]

IOC_TYPES = ["IP", "Domain", "URL", "Hash"]
IOC_TAGS = ["Malware", "Suspicious", "C2", "Benign"]

IP_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)

MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")

URL_REGEX = re.compile(
    r"^(https?://)"
    r"(([A-Za-z0-9-]+\.)+[A-Za-z]{2,}|"
    r"localhost|"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))"
    r"(?::\d{1,5})?"
    r"(?:/[^\s]*)?$",
    re.IGNORECASE,
)

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class IOC(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    tag = db.Column(db.String(50), nullable=False)
    source = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.String(50), nullable=False)

    network_zone = db.Column(db.String(50), nullable=True, default="Corporate IT")

    vt_status = db.Column(db.String(50), nullable=True)
    vt_malicious = db.Column(db.Integer, nullable=True)
    vt_suspicious = db.Column(db.Integer, nullable=True)
    vt_harmless = db.Column(db.Integer, nullable=True)
    vt_undetected = db.Column(db.Integer, nullable=True)
    vt_last_analysis_date = db.Column(db.String(50), nullable=True)

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
            "network_zone": self.network_zone,
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


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def ensure_ioc_columns():
    inspector = inspect(db.engine)
    columns = [col["name"] for col in inspector.get_columns("ioc")]

    if "network_zone" not in columns:
        with db.engine.connect() as conn:
            conn.execute(
                text(
                    "ALTER TABLE ioc ADD COLUMN network_zone VARCHAR(50) DEFAULT 'Corporate IT'"
                )
            )
            conn.commit()


def create_default_admin():
    existing_user = User.query.filter_by(username=DEFAULT_ADMIN_USERNAME).first()
    if not existing_user:
        user = User(username=DEFAULT_ADMIN_USERNAME)
        user.set_password(DEFAULT_ADMIN_PASSWORD)
        db.session.add(user)
        db.session.commit()
        print(
            f"[INFO] Default admin created -> username: {DEFAULT_ADMIN_USERNAME} | password: {DEFAULT_ADMIN_PASSWORD}"
        )


def is_valid_ioc_value(ioc_type: str, value: str) -> bool:
    if not ioc_type or not value:
        return False

    normalized_type = ioc_type.strip().lower()
    normalized_value = value.strip()

    if normalized_type == "ip":
        return bool(IP_REGEX.fullmatch(normalized_value))

    if normalized_type == "hash":
        return bool(
            MD5_REGEX.fullmatch(normalized_value)
            or SHA1_REGEX.fullmatch(normalized_value)
            or SHA256_REGEX.fullmatch(normalized_value)
        )

    if normalized_type == "url":
        return bool(URL_REGEX.fullmatch(normalized_value))

    if normalized_type == "domain":
        return bool(DOMAIN_REGEX.fullmatch(normalized_value))

    return False


def validate_ioc_form(value, ioc_type, tag, source, network_zone):
    if not value or not value.strip():
        return "IOC value is required."

    if not ioc_type or ioc_type not in IOC_TYPES:
        return "Invalid IOC type."

    if not tag or tag not in IOC_TAGS:
        return "Invalid IOC tag."

    if not source or not source.strip():
        return "IOC source is required."

    if network_zone not in NETWORK_ZONES:
        return "Invalid network zone."

    if not is_valid_ioc_value(ioc_type, value):
        return f"Invalid IOC value for type {ioc_type}."

    return None


with app.app_context():
    db.create_all()
    ensure_ioc_columns()
    create_default_admin()


def vt_headers():
    return {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }


def encode_url_for_vt(url_value: str) -> str:
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
    malicious = ioc.vt_malicious or 0
    suspicious = ioc.vt_suspicious or 0
    harmless = ioc.vt_harmless or 0

    if malicious >= 5:
        ioc.tag = "Malware"
    elif malicious >= 1:
        ioc.tag = "Suspicious"
    elif suspicious >= 1:
        ioc.tag = "Suspicious"
    elif malicious == 0 and suspicious == 0 and harmless >= 1:
        ioc.tag = "Benign"


def get_zone_risk_multiplier(network_zone: str) -> float:
    multipliers = {
        "Corporate IT": 1.0,
        "DMZ": 1.3,
        "OT Level 2": 1.6,
        "OT Level 1": 2.0,
        "Field Device": 2.5,
    }
    return multipliers.get(network_zone, 1.0)


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

            zone_multiplier = get_zone_risk_multiplier(ioc.network_zone or "Corporate IT")
            malicious = ioc.vt_malicious or 0
            if zone_multiplier >= 2.0 and malicious >= 1:
                ioc.tag = "Malware"

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
            zone_multiplier = get_zone_risk_multiplier(ioc.network_zone or "Corporate IT")

            c2_threshold = max(10, int(75 / zone_multiplier))
            suspicious_threshold = max(5, int(25 / zone_multiplier))

            if score >= c2_threshold:
                ioc.tag = "C2"
            elif score >= suspicious_threshold and ioc.tag not in ["Malware", "C2"]:
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


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash("Login successful.", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    search = request.args.get("search", "").strip()
    filter_type = request.args.get("type", "").strip()
    filter_tag = request.args.get("tag", "").strip()
    filter_source = request.args.get("source", "").strip()
    filter_zone = request.args.get("zone", "").strip()

    query = IOC.query

    if search:
        query = query.filter(IOC.value.ilike(f"%{search}%"))
    if filter_type:
        query = query.filter(IOC.type == filter_type)
    if filter_tag:
        query = query.filter(IOC.tag == filter_tag)
    if filter_source:
        query = query.filter(IOC.source.ilike(f"%{filter_source}%"))
    if filter_zone:
        query = query.filter(IOC.network_zone == filter_zone)

    iocs = query.order_by(IOC.id.desc()).all()
    total_iocs = len(iocs)

    tag_counts = {"Malware": 0, "Suspicious": 0, "C2": 0, "Benign": 0}
    type_counts = {"IP": 0, "Domain": 0, "URL": 0, "Hash": 0}
    zone_counts = {z: 0 for z in NETWORK_ZONES}

    for ioc in iocs:
        if ioc.tag in tag_counts:
            tag_counts[ioc.tag] += 1
        if ioc.type in type_counts:
            type_counts[ioc.type] += 1
        zone = ioc.network_zone or "Corporate IT"
        if zone in zone_counts:
            zone_counts[zone] += 1

    return render_template(
        "index.html",
        iocs=iocs,
        total_iocs=total_iocs,
        tag_counts=tag_counts,
        type_counts=type_counts,
        zone_counts=zone_counts,
        network_zones=NETWORK_ZONES,
        search=search,
        filter_type=filter_type,
        filter_tag=filter_tag,
        filter_source=filter_source,
        filter_zone=filter_zone,
        current_user=current_user,
    )


@app.route("/add_ioc", methods=["POST"])
@login_required
def add_ioc():
    data = request.form
    value = (data.get("value") or "").strip()
    ioc_type = (data.get("type") or "").strip()
    tag = (data.get("tag") or "").strip()
    source = (data.get("source") or "").strip()
    network_zone = (data.get("network_zone") or "Corporate IT").strip()

    error = validate_ioc_form(value, ioc_type, tag, source, network_zone)
    if error:
        flash(error, "danger")
        return redirect(url_for("dashboard"))

    new_ioc = IOC(
        value=value,
        type=ioc_type,
        tag=tag,
        source=source,
        network_zone=network_zone,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    db.session.add(new_ioc)
    db.session.commit()

    enrich_ioc_with_vt(new_ioc)
    if new_ioc.type.lower() == "ip":
        enrich_ioc_with_abuseipdb(new_ioc)

    flash("IOC added successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/enrich_vt/<int:ioc_id>", methods=["POST"])
@login_required
def enrich_vt(ioc_id):
    ioc = IOC.query.get_or_404(ioc_id)
    enrich_ioc_with_vt(ioc)
    flash("VirusTotal enrichment completed.", "success")
    return redirect(url_for("dashboard"))


@app.route("/api/iocs", methods=["GET"])
@login_required
def get_iocs():
    iocs = IOC.query.order_by(IOC.id.desc()).all()
    return jsonify([ioc.to_dict() for ioc in iocs])


@app.route("/enrich_abuse/<int:ioc_id>", methods=["POST"])
@login_required
def enrich_abuse(ioc_id):
    ioc = IOC.query.get_or_404(ioc_id)
    enrich_ioc_with_abuseipdb(ioc)
    flash("AbuseIPDB enrichment completed.", "success")
    return redirect(url_for("dashboard"))


@app.route("/delete_ioc/<int:ioc_id>", methods=["POST"])
@login_required
def delete_ioc(ioc_id):
    ioc = IOC.query.get_or_404(ioc_id)
    db.session.delete(ioc)
    db.session.commit()
    flash("IOC deleted successfully.", "info")
    return redirect(url_for("dashboard"))


@app.route("/edit_ioc/<int:ioc_id>", methods=["GET", "POST"])
@login_required
def edit_ioc(ioc_id):
    ioc = IOC.query.get_or_404(ioc_id)

    if request.method == "POST":
        value = (request.form.get("value") or "").strip()
        ioc_type = (request.form.get("type") or "").strip()
        tag = (request.form.get("tag") or "").strip()
        source = (request.form.get("source") or "").strip()
        network_zone = (request.form.get("network_zone") or "Corporate IT").strip()

        error = validate_ioc_form(value, ioc_type, tag, source, network_zone)
        if error:
            flash(error, "danger")
            return redirect(url_for("edit_ioc", ioc_id=ioc.id))

        ioc.value = value
        ioc.type = ioc_type
        ioc.tag = tag
        ioc.source = source
        ioc.network_zone = network_zone
        db.session.commit()

        flash("IOC updated successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("edit.html", ioc=ioc, network_zones=NETWORK_ZONES)


@app.route("/bulk_upload", methods=["POST"])
@login_required
def bulk_upload():
    file = request.files.get("file")
    if not file or file.filename == "":
        flash("No file selected for upload.", "danger")
        return redirect(url_for("dashboard"))

    try:
        stream = io.StringIO(file.stream.read().decode("utf-8"))
        reader = csv.DictReader(stream)

        inserted_count = 0
        skipped_count = 0

        for row in reader:
            value = (row.get("value") or "").strip()
            ioc_type = (row.get("type") or "").strip()
            tag = (row.get("tag") or "").strip()
            source = (row.get("source") or "").strip()
            network_zone = (row.get("network_zone") or "Corporate IT").strip()

            error = validate_ioc_form(value, ioc_type, tag, source, network_zone)
            if error:
                skipped_count += 1
                continue

            new_ioc = IOC(
                value=value,
                type=ioc_type,
                tag=tag,
                source=source,
                network_zone=network_zone,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            db.session.add(new_ioc)
            db.session.commit()

            enrich_ioc_with_vt(new_ioc)
            if new_ioc.type.lower() == "ip":
                enrich_ioc_with_abuseipdb(new_ioc)

            inserted_count += 1

        flash(
            f"Bulk upload completed. Inserted: {inserted_count}, Skipped invalid rows: {skipped_count}",
            "info",
        )
        return redirect(url_for("dashboard"))

    except Exception as e:
        return f"Bulk upload failed: {str(e)}", 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)