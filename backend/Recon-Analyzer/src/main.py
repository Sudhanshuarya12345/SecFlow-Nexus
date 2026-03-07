import logging
import os
import re
import socket

from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv

from attack.ipapi import ipapi
from attack.talos import talos
from attack.threatfox import threatfox
from attack.tor import tor
from attack.tranco import tranco
from osint.xposedornot import checkEmail
from osint.phone import validate_phone_number
from osint.username import sagemode_wrapper

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"]}})

# API prefix for all routes
API_PREFIX = '/api/Recon-Analyzer'

IP_REGEX = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
URL_REGEX = r'^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$'
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
PHONE_REGEX = r'^\+?[0-9]\d{1,14}$'


@app.route(f'{API_PREFIX}/')
@app.route('/')
def home():
    logger.info("Home endpoint accessed")
    return jsonify({
        "message": "Welcome to ReconGraph API",
        "version": "1.0.0",
        "base_url": "/api/Recon-Analyzer",
        "endpoints": {
            "/api/Recon-Analyzer/scan": "POST - Scan IP or domain for threat intelligence",
            "/api/Recon-Analyzer/footprint": "POST - Digital footprint analysis (email, phone, username)",
            "/api/Recon-Analyzer/health": "GET - Health check endpoint"
        }
    })


@app.route(f'{API_PREFIX}/health')
@app.route('/health')
def health():
    """Health check endpoint for container orchestration."""
    return jsonify({"status": "healthy"})


@app.route(f'{API_PREFIX}/scan', methods=['POST'])
@app.route('/scan', methods=['POST'])
def scan():
    """Scan an IP address or domain for threat intelligence."""
    body = request.get_json() or {}
    ip_or_domain = body.get('query')

    if not ip_or_domain:
        logger.warning("Scan request with no query provided")
        return jsonify({"error": "No IP or domain provided."}), 400

    logger.info(f"Scanning: {ip_or_domain}")
    
    ip_to_scan = None
    url_to_scan = None

    if re.match(IP_REGEX, ip_or_domain):
        ip_to_scan = ip_or_domain
        logger.info(f"Detected IP address: {ip_to_scan}")
    elif re.match(URL_REGEX, ip_or_domain):
        try:
            ip_to_scan = socket.gethostbyname(ip_or_domain)
            url_to_scan = ip_or_domain
            logger.info(f"Detected domain: {ip_or_domain} -> IP: {ip_to_scan}")
        except socket.gaierror as e:
            logger.error(f"Failed to resolve domain {ip_or_domain}: {e}")
            return jsonify({"error": f"Unable to resolve domain: {ip_or_domain}"}), 400
    else:
        logger.warning(f"Invalid input format: {ip_or_domain}")
        return jsonify({"error": "Invalid IP or domain format."}), 400

    results = {"query": ip_or_domain}

    if ip_to_scan:
        logger.info(f"Running IP-based checks for {ip_to_scan}")
        results["ipapi"] = ipapi(ip_to_scan)
        results["talos"] = talos(ip_to_scan)
        results["tor"] = tor(ip_to_scan)

    if url_to_scan:
        logger.info(f"Running domain-based checks for {url_to_scan}")
        results["tranco"] = tranco(url_to_scan)
        threatfox_result = threatfox(url_to_scan)
        if threatfox_result:
            results["threatfox"] = threatfox_result

    logger.info(f"Scan complete for {ip_or_domain}")
    return jsonify(results)


@app.route(f'{API_PREFIX}/footprint', methods=['POST'])
@app.route('/footprint', methods=['POST'])
def footprint():
    """Analyze digital footprint based on email, phone, or username."""
    body = request.get_json() or {}
    query = body.get('query')

    if not query:
        logger.warning("Footprint request with no query provided")
        return jsonify({"error": "No query provided. Please provide an email, phone number, or username."}), 400

    logger.info(f"Footprint analysis for: {query}")
    
    results = {"query": query}

    if re.match(EMAIL_REGEX, query):
        logger.info(f"Detected email: {query}")
        results["type"] = "email"
        try:
            results["email_scan"] = checkEmail(query)
        except Exception as e:
            logger.error(f"Email scan failed: {e}")
            results["email_scan"] = {"error": str(e)}
    elif re.match(PHONE_REGEX, query):
        logger.info(f"Detected phone: {query}")
        results["type"] = "phone"
        try:
            results["phone_scan"] = validate_phone_number(query)
        except Exception as e:
            logger.error(f"Phone scan failed: {e}")
            results["phone_scan"] = {"error": str(e)}
    else:
        logger.info(f"Detected username: {query}")
        results["type"] = "username"
        try:
            results["username_scan"] = sagemode_wrapper(query)
        except Exception as e:
            logger.error(f"Username scan failed: {e}")
            results["username_scan"] = {"error": str(e)}

    logger.info(f"Footprint analysis complete for {query}")
    return jsonify(results)


if __name__ == "__main__":
    logger.info("Starting ReconGraph server in development mode on port 5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
