"""
api.py — FastAPI backend for the AI-Powered Firewall Rule Optimizer.

Run locally:
    uvicorn api:app --reload --port 8000

Run on AWS EC2:
    uvicorn api:app --host 0.0.0.0 --port 8000

Interactive docs available at:
    http://localhost:8000/docs
"""

import os
import uuid
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from parser.parser_facade import ParseError, RuleParser
from pipeline import FirewallOptimizer

app = FastAPI(
    title="AI-Powered Firewall Rule Optimizer",
    description=(
        "Upload a firewall rule file (iptables, JSON, CSV, Cisco ACL, or AWS SG) "
        "and receive a full conflict analysis, ML-based reordering, and "
        "actionable recommendations."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory report store — replace with Redis/RDS for production
REPORTS: dict = {}
OUTPUT_DIR = Path("./outputs")
OUTPUT_DIR.mkdir(exist_ok=True)


# ─── Health check ─────────────────────────────────────────────────────────────

@app.get("/", tags=["health"])
def root():
    return {"status": "running", "version": "1.0.0", "docs": "/docs"}


@app.get("/health", tags=["health"])
def health():
    return {"status": "ok"}


# ─── Core analysis endpoint ───────────────────────────────────────────────────

@app.post("/api/analyze", tags=["analysis"])
async def analyze(
    file: UploadFile = File(..., description="Firewall rule file"),
    format: str = None,
    synthetic_logs: int = 1000,
):
    """
    Upload a firewall rule file and receive a complete audit report.

    - **file**: Rule file in any supported format
    - **format**: Force format detection (iptables / json / csv / cisco / aws).
                  Leave empty for auto-detect.
    - **synthetic_logs**: Number of synthetic traffic records for ML optimization.
                          Set to 0 to skip ML reordering.
    """
    suffix = Path(file.filename).suffix if file.filename else ".txt"

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        content = await file.read()
        tmp.write(content)
        tmp_path = tmp.name

    try:
        optimizer = FirewallOptimizer(verbose=False)
        result = optimizer.analyze(
            rules_filepath=tmp_path,
            rule_format=format,
            synthetic_logs=synthetic_logs,
        )

        report_id = str(uuid.uuid4())[:8]
        report_dir = OUTPUT_DIR / report_id
        report_dir.mkdir(parents=True)

        paths = result.export(str(report_dir))
        REPORTS[report_id] = {"result": result, "paths": paths,
                               "filename": file.filename}

        return {
            "report_id": report_id,
            "filename": file.filename,
            "summary": {
                "total_rules":      result.conflict_report.total_rules,
                "elapsed_sec":      round(result.elapsed_sec, 3),
                "contradictions":   result.conflict_report.contradiction_count,
                "shadows":          result.conflict_report.shadow_count,
                "duplicates":       result.conflict_report.duplicate_count,
                "permissive":       result.conflict_report.permissive_count,
                "redundant":        result.conflict_report.redundant_count,
                "recommendations":  len(result.recommendations),
                "speedup": round(result.opt_result.estimated_speedup, 2)
                           if result.opt_result else None,
                "policy_equivalent": result.opt_result.policy_equivalent
                                     if result.opt_result else None,
            },
            "rules":           [r.to_dict() for r in result.original_rules],
            "findings":        [f.to_dict() for f in result.conflict_report.findings],
            "recommendations": [r.to_dict() for r in result.recommendations],
            "download_links": {
                fmt: f"/api/report/{report_id}/download/{fmt}"
                for fmt in ["json", "markdown", "iptables_optimized", "csv", "yaml"]
            },
        }

    except ParseError as exc:
        raise HTTPException(status_code=400,
                            detail=f"Could not parse rule file: {exc}")
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        os.unlink(tmp_path)


# ─── Report retrieval ─────────────────────────────────────────────────────────

@app.get("/api/reports", tags=["reports"])
def list_reports():
    """List all cached report IDs."""
    return {
        "reports": [
            {"report_id": rid, "filename": data["filename"]}
            for rid, data in REPORTS.items()
        ]
    }


@app.get("/api/report/{report_id}", tags=["reports"])
def get_report(report_id: str):
    """Fetch a full cached report by ID."""
    if report_id not in REPORTS:
        raise HTTPException(status_code=404, detail="Report not found")
    result = REPORTS[report_id]["result"]
    return {
        "report_id":       report_id,
        "filename":        REPORTS[report_id]["filename"],
        "rules":           [r.to_dict() for r in result.original_rules],
        "findings":        [f.to_dict() for f in result.conflict_report.findings],
        "recommendations": [r.to_dict() for r in result.recommendations],
    }


@app.get("/api/report/{report_id}/download/{fmt}", tags=["reports"])
def download_report(report_id: str, fmt: str):
    """Download an exported file. fmt: json | markdown | iptables_optimized | csv | yaml"""
    if report_id not in REPORTS:
        raise HTTPException(status_code=404, detail="Report not found")

    paths = REPORTS[report_id]["paths"]
    if fmt not in paths:
        raise HTTPException(status_code=404,
                            detail=f"Format '{fmt}' not available. "
                                   f"Available: {list(paths.keys())}")

    media = {
        "json":                "application/json",
        "markdown":            "text/markdown",
        "iptables_optimized":  "text/plain",
        "iptables_original":   "text/plain",
        "csv":                 "text/csv",
        "yaml":                "text/yaml",
    }
    return FileResponse(
        paths[fmt],
        media_type=media.get(fmt, "text/plain"),
        filename=Path(paths[fmt]).name,
    )