from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import json
from pathlib import Path
from datetime import datetime

from wireless_analyzer import WirelessAnalyzer, build_report, print_report
import io
from contextlib import redirect_stdout

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI()

# allow frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def run_analysis(log_text, start_dt=None, end_dt=None):
    az = WirelessAnalyzer(start_dt=start_dt, end_dt=end_dt)
    az.ingest(log_text)
    report = build_report(az)
    
    # Save text report to disk
    with open(BASE_DIR / "wireless_report.txt", "w", encoding="utf-8") as f:
        with redirect_stdout(f):
            print_report(report, az)
            
    # Save JSON report to disk
    with open(BASE_DIR / "wireless_report.json", "w", encoding="utf-8") as f:
        # We need a custom serializer for datetime, or just use str
        json.dump(report, f, indent=2, default=str)
    
    return report


def run_bundled_analysis(log_name, start_dt=None, end_dt=None):
    log_text = (BASE_DIR / log_name).read_text(errors="ignore")
    return run_analysis(log_text, start_dt, end_dt)

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

    return run_bundled_analysis("snmptrap-20250521.log", start_dt, end_dt)


@app.get("/download/txt")
def download_txt():
    file_path = BASE_DIR / "wireless_report.txt"
    if file_path.exists():
        return FileResponse(file_path, media_type="text/plain", filename="wireless_report.txt")
    return {"error": "File not found"}

@app.get("/download/json")
def download_json():
    file_path = BASE_DIR / "wireless_report.json"
    if file_path.exists():
        return FileResponse(file_path, media_type="application/json", filename="wireless_report.json")
    return {"error": "File not found"}

app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")