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
from datetime import datetime
from pathlib import Path
import re

driver = None
driver_lock = threading.Lock()

pause_requested = False
stop_requested = False
scan_active = False
scan_paused = False
state_lock = threading.Lock()

app = Flask(__name__)
CORS(app)

APP_DIR = Path(__file__).resolve().parent
SCANS_DIR = APP_DIR / "scans"
FLS_DIR = SCANS_DIR / "scans_fls"
E57_DIR = SCANS_DIR / "scans_e57"

WRAPPER_BASE = "http://127.0.0.1:8765"

def ensure_dirs():
    FLS_DIR.mkdir(parents=True, exist_ok=True)
    E57_DIR.mkdir(parents=True, exist_ok=True)

def now_stamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def _safe_slug(name: str) -> str:
    s = (name or "").strip().lower()
    s = s.replace(" ", "_")
    s = re.sub(r"[^a-z0-9_\-\.]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "scan"

def _derive_base_from_enclosure(enclosure_filename: str) -> str:
    """
    enclosure_filename is typically like: IP50_Column6A_Scan_140.fls.zip
    We want base: ip50_column6a_scan_140
    """
    if not enclosure_filename:
        return "scan"

    name = Path(enclosure_filename).name
    if name.lower().endswith(".zip"):
        name = name[:-4]
    if name.lower().endswith(".fls"):
        name = name[:-4]
    return _safe_slug(name)

def _get_latest_scan_info(base_url: str):
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

def _download_enclosure_to_disk(base_url: str, enclosure_filename: str, camera_suffix: str, display_name: str):
    resp = requests.get(f"{base_url}/lswebapi/scans", verify=False, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    embedded = data.get("_embedded", {})

    target_href = None
    for _, scan_info in embedded.items():
        enclosure = scan_info.get("_links", {}).get("enclosure", {})
        enclosure_href = enclosure.get("href", "")
        enclosure_file = enclosure_href.split("/")[-1]
        if enclosure_filename == enclosure_file:
            target_href = enclosure_href
            break

    if not target_href:
        raise RuntimeError(f"Remote enclosure not found: {enclosure_filename}")

    download_url = f"{base_url}{target_href}"
    file_response = requests.get(download_url, verify=False, timeout=120)
    if file_response.status_code != 200:
        raise RuntimeError(f"Failed to download enclosure: HTTP {file_response.status_code}")

    safe_display = (display_name or "scan").replace(" ", "_")
    local_name = f"{safe_display}_cam{camera_suffix}_{now_stamp()}_{enclosure_filename}"
    out_path = FLS_DIR / local_name
    out_path.write_bytes(file_response.content)
    return str(out_path)

def _convert_latest_to_e57(preferred_name: str | None = None):
    """
    Calls wrapper to export latest scan from DefaultProject as E57.
    If preferred_name is provided, wrapper will rename the produced file to that.
    Returns (run_folder_name, e57_filename)
    """
    payload = {"format": "e57"}
    if preferred_name:
        payload["out_name"] = preferred_name

    r = requests.post(f"{WRAPPER_BASE}/convert/latest", json=payload, timeout=60 * 60)
    data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    if r.status_code != 200 or data.get("status") != "ok":
        raise RuntimeError(f"Converter failed: {data}")

    run_dir = data.get("run_dir", "")
    primary = data.get("primary_file", "")
    run_name = Path(run_dir).name if run_dir else ""
    if not run_name or not primary:
        raise RuntimeError(f"Converter returned no output: {data}")

    return run_name, primary

@app.route('/trigger-scan', methods=['GET'])
def trigger_scan():
    global driver, pause_requested, stop_requested, scan_active, scan_paused
    ensure_dirs()

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
        print(f"[SCAN] Latest scan: {display_name} / {download_name}")

        if not download_name:
            return jsonify({
                "status": "ok",
                "message": "Scan complete (could not resolve download name)",
                "file_name": display_name or "unknown",
                "download_name": None
            }), 200

        local_fls = _download_enclosure_to_disk(
            base_url=base_url,
            enclosure_filename=download_name,
            camera_suffix=str(ip_suffix),
            display_name=display_name or "unknown"
        )
        print(f"[SCAN] Saved FLS zip to: {local_fls}")

        base = _derive_base_from_enclosure(download_name)
        preferred_e57 = f"{base}.e57"

        run_name, e57_name = _convert_latest_to_e57(preferred_name=preferred_e57)
        print(f"[SCAN] Converted E57: run={run_name}, file={e57_name}")

        return jsonify({
            "status": "ok",
            "message": "Scan complete and converted",
            "file_name": display_name or "unknown",
            "download_name": download_name,
            "local_fls": local_fls,
            "e57_run": run_name,
            "e57_name": e57_name,
            "e57_preferred": preferred_e57
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

@app.route("/download-e57", methods=["GET"])
def download_e57():
    run = request.args.get("run", "")
    name = request.args.get("name", "")
    if not run or not name:
        return jsonify({"status": "error", "message": "run and name are required"}), 400

    url = f"{WRAPPER_BASE}/download"
    r = requests.get(url, params={"run": run, "name": name}, timeout=300)
    if r.status_code != 200:
        return jsonify({"status": "error", "message": f"Wrapper download failed: {r.status_code}"}), 502

    return send_file(
        BytesIO(r.content),
        download_name=name,
        as_attachment=True,
        mimetype="application/octet-stream"
    )

@app.route('/')
def serve_html():
    return send_file("index.html")

if __name__ == '__main__':
    ensure_dirs()
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)
