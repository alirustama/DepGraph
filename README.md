# DepGraph

DepGraph is a software supply-chain risk explorer for projects, packages,
versions, vulnerabilities, and maintainers stored in CognoDB. It helps an
engineering team trace transitive dependencies, measure vulnerability blast
radius, find remediation paths, and identify maintainer concentration risk.

## Why a graph database?

Dependency analysis is a variable-depth path problem. A project can require a
package directly, while that package depends on other packages through several
versions. CognoDB and openCypher represent those relationships directly, so
variable-length traversals preserve both the path and its depth. A relational
implementation would need recursive queries or precomputed dependency levels.

## Features

- Project dependency trees, including transitive packages
- Package versions, maintainers, reverse dependents, and exposed projects
- Vulnerability detail pages with blast-radius paths
- Shortest project-to-package paths
- Maintainer concentration risk ranking
- Interactive dependency graphs using vis-network
- Clear loading, empty, error, and database-unavailable states

## Architecture

```text
Browser -> FastAPI -> Neo4j Python driver -> CognoDB over Bolt
             |
             +-> static frontend
```

The backend and no-build frontend are served by one FastAPI process. See
[docs/architecture.md](docs/architecture.md) for the data model and request
flow.
## Application evidence

Hosted application demo: <https://depgraph-1-broj.onrender.com>

The repository includes a short screen recording and captured UI frames:

- [Short screen recording](docs/depgraph-launch-walkthrough.mp4)
- [Projects](docs/screenshots/01-projects.png)
- [Project detail](docs/screenshots/02-project-detail.png)
- [Package detail](docs/screenshots/03-package-detail.png)
- [Vulnerability blast radius](docs/screenshots/04-vulnerability-blast-radius.png)
- [Maintainer risk](docs/screenshots/05-maintainer-risk.png)

Do not publish database credentials in a screenshot or recording.

## Repository layout

```text
app/                  FastAPI application, database layer, queries, seed data
scripts/              Maintenance commands, including the database seeder
static/               HTML, CSS, and JavaScript frontend
docs/                 Architecture notes and portfolio evidence
tests/                Application smoke tests
.env.example          Safe local configuration template
Procfile              Render process command
render.yaml           Render Blueprint configuration
requirements.txt      Python dependencies
runtime.txt           Python runtime pin
```


## Prerequisites

- Python 3.11
- A running CognoDB instance with Bolt access
- Git and `uv` (recommended) or standard Python virtual-environment tooling

## Local setup

### 1. Clone the GitHub repository

```powershell
git clone https://github.com/<your-account>/<your-repository>.git
cd <your-repository>
```

Replace the URL and directory with the repository you created on GitHub.

### 2. Create a Python environment

Windows with `uv`:

```powershell
uv python install 3.11
uv venv --python 3.11 .venv
uv pip install --python .venv\Scripts\python.exe -r requirements.txt
```

Standard Python:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows PowerShell, activate with `.\.venv\Scripts\Activate.ps1` when using
standard Python tooling.

### 3. Configure CognoDB

1. Create a CognoDB Cloud instance and wait for it to be running.
2. Copy the Bolt URI, username, and generated password from the connection
   panel.
3. Copy `.env.example` to `.env`.
4. Put the connection values in `.env`.
5. Keep `COGNODB_DATABASE=neo4j` unless your instance specifies another name.

Never commit `.env`. It is ignored by `.gitignore`.

### 4. Seed the demo graph

The default command clears the selected database, creates uniqueness
constraints, and loads the fictional demo graph:

```powershell
.\.venv\Scripts\python.exe scripts\seed.py
```

To preserve existing data and merge the demo records:

```powershell
.\.venv\Scripts\python.exe scripts\seed.py --no-wipe
```

### 5. Run the application

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>. Check the database connection at
<http://127.0.0.1:8000/api/health>.

## GitHub publishing

1. Create a new empty repository on GitHub.
2. Do not add a second README, license, or `.gitignore` during creation.
3. From the project root, review `git status` and confirm `.env` and `.venv/`
   are ignored.
4. Initialize and publish the repository:

```powershell
git init
git add .
git status
git commit -m "DepGraph portfolio repository"
git branch -M main
git remote add origin https://github.com/<your-account>/<your-repository>.git
git push -u origin main
```

Before pushing, inspect `git status` and ensure no credential file, virtual
environment, cache, or generated secret is staged.

## Render deployment

The repository includes `render.yaml` and `Procfile` for a Render web service.

1. Push the project to GitHub using the steps above.
2. In Render, select **New > Blueprint** and choose the GitHub repository.
3. Apply the blueprint from `render.yaml`.
4. In the Render service environment, set `COGNODB_URI`, `COGNODB_USER`, and
   `COGNODB_PASSWORD` as secret values. `COGNODB_DATABASE` defaults to `neo4j`.
5. Deploy and wait for the health check to finish.
6. Seed CognoDB once from a trusted local shell using the same database
   credentials. The deployment never wipes the database automatically.
7. Open the Render service URL and verify `/api/health` returns `ok: true`.
8. Add the public URL to your portfolio or submission page.

The production process is:

```text
uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

## API and Cypher coverage

The API exposes project, package, vulnerability, blast-radius,
maintainer-risk, graph, and shortest-path endpoints. The Cypher statements
are kept in [app/queries.py](app/queries.py), and values are passed through
Neo4j driver parameters.

Important traversals include:

- `DEPENDS_ON*0..6` for transitive dependency and blast-radius analysis
- `shortestPath()` for remediation inspection
- Reverse package-to-project traversal for impact analysis
- Maintainer-to-package-to-project traversal for concentration risk

## Portfolio evidence

The repository includes a short local walkthrough and captured UI frames:

- [Launch walkthrough](docs/depgraph-launch-walkthrough.mp4)
- [Projects](docs/screenshots/01-projects.png)
- [Project detail](docs/screenshots/02-project-detail.png)
- [Package detail](docs/screenshots/03-package-detail.png)
- [Vulnerability blast radius](docs/screenshots/04-vulnerability-blast-radius.png)
- [Maintainer risk](docs/screenshots/05-maintainer-risk.png)

Replace the public demo placeholder with the actual Render URL after
deployment. Do not publish database credentials in a screenshot or recording.

## Validation

Run the smoke tests and Python syntax check before publishing:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m compileall -q app scripts
```

For a live service, also check:

```powershell
Invoke-WebRequest http://127.0.0.1:8000/ -UseBasicParsing
Invoke-WebRequest http://127.0.0.1:8000/api/health -UseBasicParsing
```

## License

This project is released under the [MIT License](LICENSE).
