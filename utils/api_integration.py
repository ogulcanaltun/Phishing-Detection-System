import requests
import base64
from urllib.parse import urlparse
import socket
from datetime import datetime

class APIResult:
    def __init__(self, is_malicious=False, confidence=0, details=None):
        self.is_malicious = is_malicious
        self.confidence = confidence
        self.details = details or {}

def encode_url(url):
    """Encode URL in Base64 for VirusTotal API."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def calculate_threat_score(stats):
    """Calculate a normalized threat score from VirusTotal statistics."""
    total_scanners = sum(stats.values())
    if total_scanners == 0:
        return 0
    
    # Weight malicious results more heavily
    weighted_score = (stats.get('malicious', 0) * 1.0 + 
                     stats.get('suspicious', 0) * 0.5) / total_scanners * 100
    return round(weighted_score, 2)

def check_virustotal(url):
    """Enhanced VirusTotal API integration with structured results."""
    api_key = ""
    headers = {"x-apikey": api_key}
    
    try:
        encoded_url = encode_url(url)
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{encoded_url}", 
            headers=headers,
            timeout=10
        )
        
        if response.status_code != 200:
            return APIResult(
                is_malicious=False,
                confidence=0,
                details={"error": f"API Error: {response.status_code}"}
            )

        data = response.json()
        attributes = data['data']['attributes']
        stats = attributes['last_analysis_stats']
        
        # Calculate threat score
        threat_score = calculate_threat_score(stats)
        
        details = {
            "last_analysis_date": datetime.fromtimestamp(attributes['last_analysis_date']).strftime('%Y-%m-%d %H:%M:%S'),
            "total_scans": sum(stats.values()),
            "detection_summary": {
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "harmless": stats.get('harmless', 0),
                "undetected": stats.get('undetected', 0)
            },
            "threat_score": threat_score,
            "categories": attributes.get('categories', {}),
            "outgoing_links": attributes.get('outgoing_links', [])
        }

        return APIResult(
            is_malicious=(threat_score > 10),  # Consider malicious if threat score > 10%
            confidence=threat_score,
            details=details
        )

    except Exception as e:
        return APIResult(
            is_malicious=False,
            confidence=0,
            details={"error": f"Request failed: {str(e)}"}
        )

def check_urlscan(url):
    """Enhanced urlscan.io API integration with structured results."""
    api_key = ""
    headers = {"API-Key": api_key}
    data = {"url": url, "visibility": "public"}
    
    try:
        response = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers,
            json=data,
            timeout=10
        )
        
        if response.status_code != 200:
            return APIResult(
                is_malicious=False,
                confidence=0,
                details={"error": f"API Error: {response.status_code}"}
            )

        result = response.json()
        details = {
            "scan_id": result.get('uuid'),
            "scan_url": result.get('result'),
            "api_url": result.get('api'),
            "country": result.get('country'),
            "submission_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        return APIResult(
            is_malicious=False,  # Initial scan doesn't provide malicious status
            confidence=0,
            details=details
        )

    except Exception as e:
        return APIResult(
            is_malicious=False,
            confidence=0,
            details={"error": f"Request failed: {str(e)}"}
        )

def format_api_results(virustotal_result, urlscan_result):
    """Format API results for display."""
    results = {
        "summary": {
            "threat_level": "High" if virustotal_result.confidence > 50 else 
                          "Medium" if virustotal_result.confidence > 10 else "Low",
            "confidence_score": virustotal_result.confidence,
            "total_scanners": virustotal_result.details.get("total_scans", 0)
        },
        "virustotal": {
            "is_malicious": virustotal_result.is_malicious,
            "threat_score": virustotal_result.details.get("threat_score", 0),
            "detection_summary": virustotal_result.details.get("detection_summary", {}),
            "last_scan": virustotal_result.details.get("last_analysis_date", "N/A")
        },
        "urlscan": {
            "scan_id": urlscan_result.details.get("scan_id", "N/A"),
            "scan_url": urlscan_result.details.get("scan_url", "N/A"),
            "country": urlscan_result.details.get("country", "Unknown")
        }
    }
    
    if "error" in virustotal_result.details:
        results["virustotal"]["error"] = virustotal_result.details["error"]
    if "error" in urlscan_result.details:
        results["urlscan"]["error"] = urlscan_result.details["error"]
    
    return results