# OT Threat Intelligence Dashboard

A SOC-style threat intelligence dashboard for OT/ICS environments.
Live Demo : https://ot-threat-intel-dashboard.onrender.com/
## Features

- IOC management for IP, Domain, URL, and Hash
- VirusTotal enrichment
- AbuseIPDB enrichment
- Auto-tagging
- Bulk CSV upload
- Filtering and search
- Edit and delete actions
- Charts for tag and IOC type distribution

## Tech Stack

- Flask
- SQLite
- HTML/CSS
- Chart.js
- VirusTotal API
- AbuseIPDB API

## Run locally

```bash
venv\Scripts\activate
pip install -r requirements.txt
py app.py
