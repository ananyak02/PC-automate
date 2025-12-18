from flask import Flask, send_file, Response, jsonify, request
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import requests
import time
from flask_cors import CORS
from io import BytesIO
import threading

# --- Scan Bridge v1 imports ---
import uuid
from datetime import datetime

driver = None
driver_lock = threading.Lock()

# Flags for pause/stop
pause_requested = False
stop_requested = False
scan_active = False
scan_paused = False
state_lock = threading.Lock()

app = Flask(__name__)
CORS(app)

# ----------------------------
# Helpers
# ----------------------------

def _get_latest_scan_info(base_url: str):
    """
    Returns (display_name, download_name) for the latest scan.
    display_name: scan_info["name"] (e.g., IP50_Column6A_Scan_128)
    download_name: enclosure file name (e.g., IP50_Column6A_Scan_128.fls.zip)
    """
    resp = requests.get(f"{base_url}/lswebapi/scans", verify=False, timeout=15)
    resp.raise_for_status()

    data = resp.json()
    embedded = data.get("_embedded", {})
    if not embedded:
        return None, None

    latest = None
    latest_time = -1

    for _, scan_info in embedded.items():
        rt = scan_info.get("recordingTime", -1)
        if rt is None:
            rt = -1
        if rt > latest_time:
            latest_time = rt
            latest = scan_info

    if not latest:
        return None, None

    display_name = latest.get("name")
    enclosure_href = (latest.get("_links", {})
                           .get("enclosure", {})
                           .get("href", ""))

    download_name = enclosure_href.split("/")[-1] if enclosure_href else None
    return display_name, download_name


# ----------------------------
# FARO Scan API (your existing endpoints)
# ----------------------------

@app.route('/trigger-scan', methods=['GET'])
def trigger_scan():
    global driver, pause_requested, stop_requested, scan_active, scan_paused

    ip_suffix = request.args.get('ip', default='50')
    print(f"[SCAN] Starting scan for IP: {ip_suffix}")
    base_url = f"https://141.70.213.{ip_suffix}"
    full_url = f"{base_url}/"

    try:
        with state_lock:
            pause_requested = False
            stop_requested = False
            scan_active = True
            scan_paused = False

        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--ignore-certificate-errors")
        chrome_options.add_argument("--allow-insecure-localhost")

        with driver_lock:
            driver = webdriver.Chrome(options=chrome_options)

        driver.get(full_url)
        print("[SCAN] Page loaded")

        try:
            WebDriverWait(driver, 15).until(
                EC.element_to_be_clickable((By.CLASS_NAME, "sui_buttonStartScan"))
            ).click()
        except Exception:
            WebDriverWait(driver, 15).until(
                EC.element_to_be_clickable((By.CLASS_NAME, "sui_buttonPreviewCommon"))
            ).click()

        print("[SCAN] Start button clicked")

        WebDriverWait(driver, 15).until(
            EC.element_to_be_clickable((By.ID, "sui_alertFirstButton"))
        ).click()

        print("[SCAN] Alert accepted, scan started")
        time.sleep(3)

        deadline = time.time() + 500
        stopped_by_user = False

        while time.time() < deadline:
            with state_lock:
                do_pause = pause_requested
                do_stop = stop_requested
                is_paused = scan_paused
                if do_pause:
                    pause_requested = False
                if do_stop:
                    stop_requested = False

            if do_stop:
                print("[SCAN] Stop requested - executing...")
                try:
                    stop_btn = WebDriverWait(driver, 10).until(
                        EC.element_to_be_clickable((By.CLASS_NAME, "osr_icon_stopButton"))
                    )
                    stop_btn.click()
                    print("[SCAN] Stop button clicked")
                    time.sleep(1)

                    delete_btn = WebDriverWait(driver, 15).until(
                        EC.element_to_be_clickable((By.ID, "sui_alertLastButton"))
                    )
                    delete_btn.click()
                    print("[SCAN] Scan deleted")

                    stopped_by_user = True
                    break
                except Exception as e:
                    print(f"[SCAN] Stop failed: {repr(e)}")

            if do_pause and not is_paused:
                print("[SCAN] Pause requested - executing...")
                try:
                    pause_btn = WebDriverWait(driver, 5).until(
                        EC.presence_of_element_located((By.CLASS_NAME, "sui_buttonPauseScan"))
                    )
                    btn_classes = pause_btn.get_attribute("class") or ""
                    print(f"[SCAN] Pause button classes: {btn_classes}")

                    if "sui_buttonInactivePauseScan" not in btn_classes:
                        driver.execute_script("arguments[0].click();", pause_btn)
                        print("[SCAN] Pause clicked successfully")
                        with state_lock:
                            scan_paused = True
                        time.sleep(1)
                    else:
                        print("[SCAN] Pause inactive - retrying later")
                        with state_lock:
                            pause_requested = True
                except Exception as e:
                    print(f"[SCAN] Pause failed: {repr(e)}")

            if not is_paused:
                try:
                    WebDriverWait(driver, 1).until(
                        EC.element_to_be_clickable((By.CLASS_NAME, "sui_buttonPreviewCommon"))
                    )
                    print("[SCAN] Scan complete - Start button visible")
                    break
                except TimeoutException:
                    pass
            else:
                time.sleep(2)

            time.sleep(0.5)

        with state_lock:
            scan_active = False
            scan_paused = False

        with driver_lock:
            try:
                driver.quit()
            except Exception:
                pass
            driver = None

        if stopped_by_user:
            return jsonify({"status": "ok", "message": "Scan stopped and deleted"}), 200

        display_name, download_name = _get_latest_scan_info(base_url)

        if not download_name:
            return jsonify({
                "status": "ok",
                "message": "Scan complete (could not resolve download name)",
                "file_name": display_name or "unknown",
                "download_name": None
            }), 200

        return jsonify({
            "status": "ok",
            "message": "Scan complete",
            "file_name": display_name or "unknown",
            "download_name": download_name
        }), 200

    except Exception as e:
        print(f"[SCAN] ERROR: {repr(e)}")
        with state_lock:
            scan_active = False
            scan_paused = False
        with driver_lock:
            try:
                if driver is not None:
                    driver.quit()
            except Exception:
                pass
            driver = None
        return Response(f"Error occurred: {str(e)}", status=500)


@app.route('/pause-scan', methods=['GET'])
def pause_scan():
    global pause_requested, scan_active
    with state_lock:
        if not scan_active:
            return jsonify({"status": "error", "message": "No active scan session"}), 400
        pause_requested = True
    print("[API] Pause requested")
    return jsonify({"status": "ok", "message": "Pause requested"}), 200


@app.route('/stop-scan', methods=['GET'])
def stop_scan():
    global stop_requested, scan_active
    with state_lock:
        if not scan_active:
            return jsonify({"status": "error", "message": "No active scan session"}), 400
        stop_requested = True
    print("[API] Stop requested")
    return jsonify({"status": "ok", "message": "Stop requested"}), 200


@app.route('/download-file', methods=['GET'])
def download_file():
    ip_suffix = request.args.get('ip', default='50')
    base_url = f"https://141.70.213.{ip_suffix}"
    file_name = request.args.get('name')

    print(f"[DOWNLOAD] Requesting file: {file_name}")

    if not file_name:
        return jsonify({"status": "error", "message": "Missing file name"}), 400

    try:
        response = requests.get(f"{base_url}/lswebapi/scans", verify=False, timeout=15)
        if response.status_code != 200:
            return jsonify({"status": "error", "message": "Failed to fetch scan list"}), 502

        data = response.json()
        embedded = data.get("_embedded", {})
        target_href = None

        for _, scan_info in embedded.items():
            enclosure = scan_info.get("_links", {}).get("enclosure", {})
            enclosure_href = enclosure.get("href", "")
            enclosure_file = enclosure_href.split("/")[-1]
            if file_name == enclosure_file:
                target_href = enclosure_href
                break

        if not target_href:
            return jsonify({"status": "error", "message": "File not found on remote server"}), 404

        download_url = f"{base_url}{target_href}"
        print(f"[DOWNLOAD] Downloading from: {download_url}")

        file_response = requests.get(download_url, verify=False, timeout=60)
        if file_response.status_code != 200:
            return jsonify({"status": "error", "message": "Failed to download file"}), 502

        return send_file(
            BytesIO(file_response.content),
            download_name=file_name,
            as_attachment=True,
            mimetype="application/zip"
        )

    except Exception as e:
        print(f"[DOWNLOAD] ERROR: {repr(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500


# ----------------------------
# Scan Bridge v1 (Ubuntu job queue)
# ----------------------------

jobs = {}       # job_id -> job dict
job_queue = []  # ordered job ids
jobs_lock = threading.Lock()

def now_iso():
    return datetime.utcnow().isoformat() + "Z"


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/bridge/jobs", methods=["POST"])
def bridge_create_job():
    payload = request.get_json(force=True, silent=True) or {}

    camera_ip_suffix = str(payload.get("camera_ip_suffix", "50"))
    workspace = payload.get("workspace")
    outdir = payload.get("outdir")
    scan_index = payload.get("scan_index", None)  # optional

    if not workspace or not outdir:
        return jsonify({"status": "error", "message": "workspace and outdir are required"}), 400

    job_id = str(uuid.uuid4())
    job = {
        "job_id": job_id,
        "state": "QUEUED",
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "assigned_to": None,

        "camera_ip_suffix": camera_ip_suffix,
        "workspace": workspace,
        "outdir": outdir,
        "scan_index": scan_index,

        "ok": None,
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "output_files": [],
    }

    with jobs_lock:
        jobs[job_id] = job
        job_queue.append(job_id)

    return jsonify({"status": "ok", "job_id": job_id, "job": job}), 200


@app.route("/bridge/jobs/next", methods=["GET"])
def bridge_next_job():
    worker = request.args.get("worker", "unknown")

    with jobs_lock:
        for job_id in job_queue:
            job = jobs.get(job_id)
            if job and job["state"] == "QUEUED":
                job["state"] = "RUNNING"
                job["assigned_to"] = worker
                job["updated_at"] = now_iso()
                return jsonify({"status": "ok", "job": job}), 200

    return jsonify({"status": "ok", "job": None}), 200


@app.route("/bridge/jobs/<job_id>/complete", methods=["POST"])
def bridge_complete_job(job_id):
    payload = request.get_json(force=True, silent=True) or {}

    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            return jsonify({"status": "error", "message": "job not found"}), 404

        job["ok"] = bool(payload.get("ok", False))
        job["exit_code"] = payload.get("exit_code")
        job["stdout"] = (payload.get("stdout", "") or "")[:200000]
        job["stderr"] = (payload.get("stderr", "") or "")[:200000]
        job["output_files"] = payload.get("output_files", []) or []

        job["state"] = "DONE" if job["ok"] else "FAILED"
        job["updated_at"] = now_iso()

    return jsonify({"status": "ok", "job": job}), 200


@app.route("/bridge/jobs/<job_id>", methods=["GET"])
def bridge_get_job(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            return jsonify({"status": "error", "message": "job not found"}), 404
        return jsonify({"status": "ok", "job": job}), 200


@app.route('/')
def serve_html():
    return send_file("index.html")


if __name__ == '__main__':
    # IMPORTANT for Windows to access your Ubuntu server:
    # - host="0.0.0.0" listens on LAN
    # - keep port 5000 unless you changed it
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
