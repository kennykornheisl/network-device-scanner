from flask import Flask, render_template, jsonify
from scanner import scan_network
from datetime import datetime, timedelta
import subprocess
import shutil
from ping3 import ping
import math
import socket
import json
import os
import random

previous_devices = set()

app = Flask(__name__)

NETWORK_RANGE = "192.168.1.0/24"
DATA_FILE = "device_memory.json"

devices_state = {}
device_memory = {}
logs = []
activity_timeline = []  # ✅ FIX: ALWAYS EXISTS

# -------------------------
# LOAD MEMORY (SAFE)
# -------------------------
def load_memory():
    global device_memory

    if not os.path.exists(DATA_FILE):
        device_memory = {}
        return

    try:
        with open(DATA_FILE, "r") as f:
            content = f.read().strip()

            if not content:
                device_memory = {}
                return

            data = json.loads(content)

            # ✅ FIX: normalize old/missing fields
            for ip, mem in data.items():
                mem.setdefault("seen_count", 0)
                mem.setdefault("avg_activity", 0)
                mem.setdefault("activity_samples", [])

            device_memory = data

    except Exception:
        device_memory = {}


def save_memory():
    with open(DATA_FILE, "w") as f:
        json.dump(device_memory, f, indent=2)


load_memory()

# -------------------------
def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


MY_IP = get_my_ip()


def now():
    return datetime.now().strftime("%H:%M:%S")


def log(msg, kind=None, ip=None):
    # kind: optional category for UI coloring (e.g. 'new','left','latency','activity')
    entry = {"time": now(), "msg": msg}
    # ISO timestamp for precise filtering
    entry["ts"] = datetime.now().isoformat()
    if kind:
        entry["kind"] = kind
    if ip:
        entry["ip"] = ip
    logs.insert(0, entry)
    logs[:] = logs[:80]

# detect ollama binary path at startup (helps when PATH differs)
OLLAMA_PATH = shutil.which("ollama")
if OLLAMA_PATH:
    log(f"OLLAMA PATH: {OLLAMA_PATH}", kind="new")
else:
    log("OLLAMA not found on PATH", kind="llm")


# -------------------------
# MEMORY TRACKING (FIXED)
# -------------------------
def update_memory(device, activity):
    ip = device["ip"]

    if ip not in device_memory:
        device_memory[ip] = {
            "ip": ip,
            "mac": device["mac"],
            "vendor": device.get("vendor", "Unknown"),
            "seen_count": 0,
            "avg_activity": 0,
            "activity_samples": []
        }

    mem = device_memory[ip]

    # ✅ SAFE UPDATE
    mem["seen_count"] = mem.get("seen_count", 0) + 1

    mem["activity_samples"].append(activity)

    if len(mem["activity_samples"]) > 50:
        mem["activity_samples"].pop(0)

    mem["avg_activity"] = sum(mem["activity_samples"]) / len(mem["activity_samples"])

    save_memory()


# -------------------------
def get_metrics(ip):

    try:
        latency = ping(ip, timeout=0.4)

        if latency is None:
            # when ping times out treat as moderate latency (avoid extreme 1000ms default)
            latency = 0.5

    except:
        latency = 0.5

    latency_ms = round(latency * 1000, 2)
    # Convert latency to a score (higher = more active) using an exponential decay
    # so small latencies don't map to near-100 activity by default.
    # latency_score = 100 * exp(-latency_ms / scale)
    scale = 200.0
    latency_score = 100.0 * math.exp(-latency_ms / scale)

    mem = device_memory.get(ip, {})
    hist_avg = mem.get("avg_activity")
    last_sample = None
    samples = mem.get("activity_samples") or []
    if samples:
        last_sample = samples[-1]

    # Weighting: prefer recent latency-derived score, but include last sample and a small historical
    w_latency = 0.75
    w_last = 0.15
    w_hist = 0.10

    v_latency = latency_score
    v_last = last_sample if last_sample is not None else latency_score
    v_hist = hist_avg if hist_avg is not None else latency_score

    activity_raw = (v_latency * w_latency) + (v_last * w_last) + (v_hist * w_hist)

    # small random jitter so values vary a bit
    jitter = random.uniform(-2.0, 2.0)

    activity = round(max(0, min(100, activity_raw + jitter)), 2)

    # bandwidth estimate (KB/s) proportional to activity with realistic scaling
    # assume peak ~1000 KB/s at 100% activity
    bandwidth = round((activity / 100.0) * random.uniform(200.0, 1000.0), 2)

    return {
        "latency": latency_ms,
        "activity": activity,
        "bandwidth": bandwidth
    }


# -------------------------
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/data")
def data():
    global devices_state, activity_timeline

    scanned = scan_network(NETWORK_RANGE)

    current = {}
    activity_values = []
    latency_values = []

    for d in scanned:
        ip = d["ip"]
        metrics = get_metrics(ip)

        activity_values.append(metrics["activity"])
        latency_values.append(metrics["latency"])

        update_memory(d, metrics["activity"])

        current[ip] = {
            "ip": ip,
            "mac": d["mac"],
            "vendor": d.get("vendor", "Unknown"),
            "type": d.get("type", "Unknown"),
            "activity": metrics["activity"],
            "latency": metrics["latency"],
            "bandwidth": metrics.get("bandwidth", 0),
            "avg_activity": device_memory.get(ip, {}).get("avg_activity", metrics["activity"]),
            "seen_count": device_memory.get(ip, {}).get("seen_count", 0)
        }

    devices_state = current

    # Detect join/leave events and some anomalies
    try:
        current_set = set(current.keys())
        # New devices
        new = current_set - previous_devices
        for ip in new:
            v = current[ip].get("vendor", "Unknown")
            log(f"NEW DEVICE: {ip} ({v})", kind="new", ip=ip)

        # Left devices
        left = previous_devices - current_set
        for ip in left:
            mem = device_memory.get(ip, {})
            v = mem.get("vendor", "Unknown")
            name = mem.get("ip", ip)
            log(f"DEVICE LEFT: {name} ({v})", kind="left", ip=ip)

        # Quick anomaly checks (only log extremes to avoid spam)
        for ip, info in current.items():
            if info.get("latency", 0) > 200:
                mem = device_memory.get(ip, {})
                v = mem.get("vendor", "Unknown")
                log(f"HIGH LATENCY: {ip} - {info.get('latency')} ms ({v})", kind="latency", ip=ip)
            if info.get("activity", 0) > 98:
                mem = device_memory.get(ip, {})
                v = mem.get("vendor", "Unknown")
                log(f"HIGH ACTIVITY: {ip} - {info.get('activity')}% ({v})", kind="activity", ip=ip)

        # update previous_devices for next poll
        previous_devices.clear()
        previous_devices.update(current_set)
    except Exception:
        # keep going if logging checks fail
        pass
    # -------------------------
    # FIXED BUSY GRAPH
    # -------------------------
    busyness = round(
        sum(activity_values) / len(activity_values), 2
        if activity_values else 0
    )

    avg_latency = round(
        sum(latency_values) / len(latency_values), 2
        if latency_values else 0
    )

    activity_timeline.append({
        "time": now(),
        "value": busyness,
        "latency": avg_latency
    })

    if len(activity_timeline) > 30:
        activity_timeline.pop(0)

    return jsonify({
        "devices": list(current.values()),
        "device_memory": device_memory,
        "logs": logs,
        "my_ip": MY_IP,
        "busyness": busyness,
        "device_count": len(current),
        "timeline": activity_timeline
    })


@app.route("/api/ai_context")
def ai_context():
    return jsonify({
        "devices": devices_state,
        "memory": device_memory,
        "logs": logs[-30:],
        "summary": {
            "device_count": len(devices_state)
        }
    })


@app.route("/api/analyze")
def analyze():
    # Build prompt and call local Ollama (if available), fallback to simple summary
    try:
        # Recent events from past 10 minutes
        cutoff = datetime.now() - timedelta(minutes=10)
        recent_events = []
        for e in logs:
            ts = e.get("ts")
            try:
                if ts and datetime.fromisoformat(ts) >= cutoff:
                    recent_events.append(e)
            except Exception:
                # ignore malformed timestamps
                pass

        # Prepare prompt for LLM
        devices = list(devices_state.values())

        # Build a clearer instruction prompt so the model ANALYZES rather than echoes data
        instruction = (
            "You are a senior network operations analyst.\n"
            "Do NOT repeat or reprint the raw JSON. Instead, analyze the provided data and produce a concise, human-readable report.\n"
            "Structure the report with these sections: SUMMARY, ISSUES (with reasons), ACTIONS (recommendations), and PER-DEVICE NOTES (only for devices behaving unusually).\n"
            "Prioritize devices that have high or rapidly changing activity, high latency, or recent join/leave events. Explain why a device is suspicious and give a short recommended next step. Be concise and use bullet points where helpful.\n"
            "Output should be plain text suitable for display in a dashboard.\n"
        )

        prompt_parts = [instruction]
        prompt_parts.append("--RECENT EVENTS (last 10 minutes)--")
        prompt_parts.append(json.dumps(recent_events, indent=2))
        prompt_parts.append("--CURRENT DEVICES--")
        prompt_parts.append(json.dumps(devices, indent=2))
        prompt_parts.append("--DEVICE HISTORY--")
        prompt_parts.append(json.dumps(list(device_memory.values()), indent=2))

        prompt_text = "\n\n".join(prompt_parts)

        # Try Ollama CLI first (local). Requires 'ollama' installed and model pulled.
        def generate_with_ollama(p, model="llama3", timeout=30):
            try:
                # Prefer passing prompt via stdin to avoid shell/length issues
                exec_path = OLLAMA_PATH or "ollama"
                proc = subprocess.run([exec_path, "run", model], input=p, capture_output=True, text=True, timeout=timeout)
                rc = proc.returncode
                out = proc.stdout.strip() if proc.stdout else ""
                err = proc.stderr.strip() if proc.stderr else ""
                return {"rc": rc, "stdout": out, "stderr": err, "exec_path": exec_path}
            except Exception as ex:
                return {"rc": -1, "stdout": "", "stderr": str(ex), "exec_path": OLLAMA_PATH}

        res = generate_with_ollama(prompt_text, model="llama3")
        llm_output = None
        llm_debug = res

        if res and res.get("rc") == 0 and res.get("stdout"):
            llm_output = res.get("stdout")
        else:
            # Log the failure for debugging (trim large stderr)
            short_err = (res.get("stderr") or "No stderr").strip()[:400]
            log(f"OLLAMA FAILED: rc={res.get('rc')} err={short_err}", kind="llm")

        if not llm_output:
            # Fallback: build a simple non-LLM analysis (still informative)
            lines = []
            lines.append(f"Device count: {len(devices)}")
            if devices:
                top_active = sorted(devices, key=lambda d: d.get("activity", 0), reverse=True)[:3]
                lines.append("Top active devices:")
                for d in top_active:
                    lines.append(f" - {d.get('ip')} ({d.get('vendor', 'Unknown')}) activity={d.get('activity')}%")

            mem_items = list(device_memory.values())
            if mem_items:
                top_avg = sorted(mem_items, key=lambda m: m.get("avg_activity", 0), reverse=True)[:3]
                lines.append("Top historical activity:")
                for m in top_avg:
                    lines.append(f" - {m.get('ip')} ({m.get('vendor', 'Unknown')}) avg={round(m.get('avg_activity',0),2)}% seen={m.get('seen_count',0)}")

            if recent_events:
                lines.append("Recent events:")
                for e in recent_events[:10]:
                    lines.append(f"[{e.get('time')}] {e.get('msg')}")

            llm_output = "\n".join(lines)

        # Return analysis and debug info to help determine if ollama ran
        return jsonify({"analysis": llm_output, "llm_debug": llm_debug})
    except Exception as e:
        return jsonify({"analysis": f"Analysis failed: {e}"})


if __name__ == "__main__":
    app.run(debug=True)