from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app import queries
from app.db import DatabaseUnavailableError, verify_connectivity

app = FastAPI(title="DepGraph", description="Software supply-chain risk explorer backed by CognoDB")

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


@app.exception_handler(DatabaseUnavailableError)
async def db_unavailable_handler(_request, exc: DatabaseUnavailableError):
    # Every route that hits CognoDB funnels failures here instead of a 500 stack trace.
    return JSONResponse(status_code=503, content={"error": "database_unavailable", "message": str(exc)})


@app.get("/api/health")
def health():
    ok, message = verify_connectivity()
    status_code = 200 if ok else 503
    return JSONResponse(status_code=status_code, content={"ok": ok, "message": message})


# ---------------------------------------------------------------------------
# Listing endpoints
# ---------------------------------------------------------------------------

@app.get("/api/projects")
def api_list_projects():
    return queries.list_projects()


@app.get("/api/packages")
def api_list_packages():
    return queries.list_packages()


@app.get("/api/vulnerabilities")
def api_list_vulnerabilities():
    return queries.list_vulnerabilities()


@app.get("/api/maintainer-risk")
def api_maintainer_risk():
    return queries.maintainer_risk()


# ---------------------------------------------------------------------------
# Detail endpoints
# ---------------------------------------------------------------------------

@app.get("/api/projects/{project_name}")
def api_project_detail(project_name: str):
    detail = queries.project_detail(project_name)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"No project named '{project_name}'")
    return detail


@app.get("/api/packages/{package_name}")
def api_package_detail(package_name: str):
    detail = queries.package_detail(package_name)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"No package named '{package_name}'")
    return detail


@app.get("/api/vulnerabilities/{cve_id}")
def api_vulnerability_detail(cve_id: str):
    detail = queries.vulnerability_blast_radius(cve_id)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"No vulnerability with id '{cve_id}'")
    return detail


@app.get("/api/blast-radius/{package_name}")
def api_blast_radius(package_name: str):
    result = queries.blast_radius(package_name)
    if result is None:
        raise HTTPException(status_code=404, detail=f"No package named '{package_name}'")
    return result


@app.get("/api/path")
def api_shortest_path(project: str = Query(...), package: str = Query(...)):
    result = queries.shortest_path(project, package)
    if result is None:
        return {"chain": None, "hops": None, "message": "No dependency path found between these two."}
    return result


# ---------------------------------------------------------------------------
# Graph-shaped payloads for visualization
# ---------------------------------------------------------------------------

@app.get("/api/graph/project/{project_name}")
def api_graph_project(project_name: str):
    return queries.graph_for_project(project_name)


@app.get("/api/graph/vulnerability/{cve_id}")
def api_graph_vulnerability(cve_id: str):
    return queries.graph_for_vulnerability(cve_id)


# ---------------------------------------------------------------------------
# Frontend (static SPA)
# ---------------------------------------------------------------------------

app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
