from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import json
from pathlib import Path
from datetime import datetime

from wireless_analyzer import WirelessAnalyzer, build_report

app = FastAPI()

# allow frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)


def save_report_locally(report, log_text=None):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    json_path = REPORTS_DIR / f"wireless_report_{timestamp}.json"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    # optional: save uploaded raw log too
    if log_text:
        log_path = REPORTS_DIR / f"wireless_log_{timestamp}.log"
        with open(log_path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(log_text)

    return {
        "json_report": str(json_path),
        "raw_log": str(log_path) if log_text else None
    }



def run_analysis(log_text, start_dt=None, end_dt=None):
    az = WirelessAnalyzer(start_dt=start_dt, end_dt=end_dt)

    az.ingest(log_text)

    report = build_report(az)

    saved_files = save_report_locally(report, log_text)

    report["_saved_files"] = saved_files

    return report

@app.post("/api/analyze")
async def analyze(
    file: UploadFile = File(...),
    start_datetime: str = Form(None),
    end_datetime: str = Form(None)
):
    content = await file.read()
    log_text = content.decode(errors="ignore")

    start_dt = None
    end_dt = None
    if start_datetime:
        try:
            start_dt = datetime.fromisoformat(start_datetime.replace('Z', '+00:00'))
        except:
            pass
    if end_datetime:
        try:
            end_dt = datetime.fromisoformat(end_datetime.replace('Z', '+00:00'))
        except:
            pass

    report = run_analysis(log_text, start_dt, end_dt)
    return report

@app.get("/api/sample")
def sample(start_datetime: str = None, end_datetime: str = None):
    log_text = Path("snmptrap-20250522.log").read_text(errors="ignore")
    
    start_dt = None
    end_dt = None
    if start_datetime:
        try:
            start_dt = datetime.fromisoformat(start_datetime.replace('Z', '+00:00'))
        except:
            pass
    if end_datetime:
        try:
            end_dt = datetime.fromisoformat(end_datetime.replace('Z', '+00:00'))
        except:
            pass
            
    return run_analysis(log_text, start_dt, end_dt)

app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")