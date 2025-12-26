import json
import subprocess
from datetime import datetime
from pathlib import Path

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

APP_DIR = Path(__file__).resolve().parent
CFG_PATH = APP_DIR / "config.json"

app = Flask(__name__)
CORS(app)

def load_cfg():
    with open(CFG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def safe_filename(name: str) -> str:
    name = (name or "").strip()
    name = name.replace("\\", "_").replace("/", "_")
    for ch in [":", "*", "?", "\"", "<", ">", "|"]:
        name = name.replace(ch, "_")
    name = "_".join(part for part in name.split() if part)
    return name

def maybe_rename_primary(run_dir: Path, produced: list[Path], requested_name: str | None) -> str | None:
    if not produced:
        return None

    primary = produced[0]
    if not requested_name:
        return primary.name

    req = safe_filename(requested_name)
    if not req:
        return primary.name

    target = run_dir / req

    if target.exists():
        stem = target.stem
        suffix = target.suffix
        k = 1
        while True:
            candidate = run_dir / f"{stem}_{k}{suffix}"
            if not candidate.exists():
                target = candidate
                break
            k += 1

    primary.rename(target)
    return target.name

@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200

@app.post("/convert/latest")
def convert_latest():
    """
    Convert the latest scan in the workspace into E57.

    Body JSON (optional overrides):
    {
      "workspace": "C:\\path\\to\\DefaultProject.lsproj",
      "format": "e57",
      "out_name": "ip50_column6a_scan_140.e57"
    }
    """
    cfg = load_cfg()
    data = request.get_json(silent=True) or {}

    workspace = data.get("workspace") or cfg["default_workspace"]
    export_fmt = (data.get("format") or "e57").lower()
    out_name = data.get("out_name")

    exe = cfg["converter_exe"]
    workspace_p = Path(workspace)
    export_base = Path(cfg["export_dir"])

    if not workspace_p.exists():
        return jsonify({"status": "error", "message": f"Workspace not found: {workspace}"}), 400
    if not Path(exe).exists():
        return jsonify({"status": "error", "message": f"Converter EXE not found: {exe}"}), 400

    ensure_dir(export_base)
    run_dir = export_base / f"run_{timestamp()}"
    ensure_dir(run_dir)

    cmd = [
        str(exe),
        "--workspace", str(workspace_p),
        "--outdir", str(run_dir),
        "--latest",
        "--process",
        "--format", export_fmt
    ]

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(run_dir),
            timeout=60 * 60
        )
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "message": "Conversion timed out"}), 504

    produced = sorted(run_dir.glob(f"*.{export_fmt}"), key=lambda p: p.stat().st_mtime, reverse=True)
    produced_names = [p.name for p in produced]

    if proc.returncode != 0:
        return jsonify({
            "status": "error",
            "returncode": proc.returncode,
            "workspace": str(workspace_p),
            "run_dir": str(run_dir),
            "files": produced_names,
            "log": (proc.stdout or "")[-20000:]
        }), 500

    if not produced:
        return jsonify({
            "status": "error",
            "returncode": proc.returncode,
            "workspace": str(workspace_p),
            "run_dir": str(run_dir),
            "files": [],
            "message": f"No .{export_fmt} produced",
            "log": (proc.stdout or "")[-20000:]
        }), 500

    primary_file = maybe_rename_primary(run_dir, produced, out_name)
    produced_after = sorted(run_dir.glob(f"*.{export_fmt}"), key=lambda p: p.stat().st_mtime, reverse=True)
    produced_after_names = [p.name for p in produced_after]

    if not primary_file:
        return jsonify({
            "status": "error",
            "workspace": str(workspace_p),
            "run_dir": str(run_dir),
            "files": produced_after_names,
            "message": "Could not resolve primary output file after conversion",
            "log": (proc.stdout or "")[-20000:]
        }), 500

    return jsonify({
        "status": "ok",
        "returncode": proc.returncode,
        "workspace": str(workspace_p),
        "run_dir": str(run_dir),
        "files": produced_after_names,
        "primary_file": primary_file,
        "log": (proc.stdout or "")[-12000:]
    }), 200

@app.get("/download")
def download():
    cfg = load_cfg()
    base = Path(cfg["export_dir"]).resolve()

    run = request.args.get("run", "")
    name = request.args.get("name", "")

    if not run or not name:
        return jsonify({"status": "error", "message": "run and name are required"}), 400

    target_dir = (base / run).resolve()
    if base not in target_dir.parents and target_dir != base:
        return jsonify({"status": "error", "message": "Invalid run dir"}), 400

    file_path = target_dir / name
    if not file_path.exists():
        return jsonify({"status": "error", "message": "File not found"}), 404

    return send_from_directory(str(target_dir), name, as_attachment=True)

if __name__ == "__main__":
    cfg = load_cfg()
    app.run(host=cfg.get("host", "0.0.0.0"), port=int(cfg.get("port", 8765)), debug=True)
