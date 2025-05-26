import os
import time
import hashlib
import requests
import math
from collections import Counter

# VirusTotal Setup
API_KEY = "5d0c9dfbef3d2f678eb845f9a8bbd651ecbe9f291633096d8e8288fc88632e83"
HEADERS = {"x-apikey": API_KEY}
VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VT_ANALYSIS_URL_TEMPLATE = "https://www.virustotal.com/api/v3/analyses/{}"

# Known Hashes (MD5 and SHA256)
known_hashes = {
    "md5": [
        hashlib.md5(b"Simulated malware content").hexdigest(),
    ],
    "sha256": [
        hashlib.sha256(b"Simulated malware content").hexdigest(),
    ]
}

# Suspicious extensions
suspicious_exts = ['.bat', '.vbs', '.ps1', '.exe', '.dll', '.scr']

# Heuristic keywords
heuristic_keywords = ['virus', 'malware', 'you have been hacked', 'keylogger', 'trojan']

# Autorun-related indicators
autorun_indicators = ['autorun.inf', 'startup', 'appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup']

def calculate_hashes(path):
    with open(path, 'rb') as f:
        data = f.read()
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }

def calculate_entropy(data):
    if not data:
        return 0
    counter = Counter(data)
    total = len(data)
    entropy = -sum((count / total) * math.log2(count / total) for count in counter.values())
    return entropy

def scan_folder_local(folder, progress):
    suspicious = []
    scanned = []

    if not folder or not os.path.exists(folder):
        return scanned, suspicious

    files = os.listdir(folder)
    total = len(files)

    for i, file in enumerate(files):
        path = os.path.join(folder, file)
        scanned.append(file)
        progress['value'] = ((i + 1) / total) * 100
        time.sleep(0.1)

        try:
            if not os.path.isfile(path):
                continue

            file_ext = os.path.splitext(file)[1].lower()
            size = os.path.getsize(path)

            # Size check
            if size < 100 or size > 50000:
                suspicious.append(file)
                continue

            # Extension check
            if file_ext in suspicious_exts:
                suspicious.append(file)
                continue

            # Behavior simulation: check if file tries to copy to startup paths
            lowered_path = path.replace("\\", "/").lower()
            if any(indicator in lowered_path for indicator in autorun_indicators):
                suspicious.append(file)
                continue

            with open(path, 'rb') as f:
                content = f.read()

            # Entropy check
            entropy = calculate_entropy(content)
            if entropy > 7.5:
                suspicious.append(file)
                continue

            # Keyword-based heuristic
            lowered = content.lower()
            if any(k.encode() in lowered for k in heuristic_keywords):
                suspicious.append(file)
                continue

            # Fake simulation: if file creates a suspicious file nearby
            if "create_" in file.lower() or "write_" in file.lower():
                suspicious.append(file)
                continue

            # Hash checks
            hashes = calculate_hashes(path)
            if hashes["md5"] in known_hashes["md5"] or hashes["sha256"] in known_hashes["sha256"]:
                suspicious.append(file)
                continue

        except Exception:
            continue

    return scanned, suspicious

# VirusTotal
def get_analysis_report(analysis_id):
    url = VT_ANALYSIS_URL_TEMPLATE.format(analysis_id)
    for _ in range(10):
        resp = requests.get(url, headers=HEADERS)
        if resp.status_code == 200:
            data = resp.json()
            status = data["data"]["attributes"]["status"]
            if status == "completed":
                return data
        time.sleep(5)
    return None

def scan_folder_virustotal(folder, progress):
    scanned = []
    results = []
    if not folder or not os.path.exists(folder):
        return scanned, results

    files = os.listdir(folder)
    total = len(files)

    for i, filename in enumerate(files):
        path = os.path.join(folder, filename)
        scanned.append(filename)
        progress['value'] = ((i + 1) / total) * 100

        if not os.path.isfile(path):
            continue

        try:
            with open(path, "rb") as f:
                files_data = {"file": (filename, f)}
                upload_resp = requests.post(VT_UPLOAD_URL, headers=HEADERS, files=files_data)

            if upload_resp.status_code == 200:
                analysis_id = upload_resp.json()["data"]["id"]
                results.append(f"{filename}: Scan submitted, waiting for report...")

                report = get_analysis_report(analysis_id)
                if report:
                    stats = report["data"]["attributes"]["stats"]
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)

                    results.append(f"{filename}: {malicious} malicious, {suspicious} suspicious detections")
                else:
                    results.append(f"{filename}: Report not ready or failed.")

            else:
                results.append(f"{filename}: Upload failed with status {upload_resp.status_code}")

            time.sleep(16)  # Respect VirusTotal rate limit

        except Exception as e:
            results.append(f"{filename}: Error {str(e)}")

    return scanned, results
