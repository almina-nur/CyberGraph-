# CyberGraph

AI-Driven Cyber Threat Intelligence & Knowledge Graph Platform.

CyberGraph aggregates cyber threat intelligence data (such as MITRE ATT&CK), structures entities and relationships in a knowledge graph, and provides query, API, visualization, and testing workflows to support threat relationship discovery and analyst investigation.

## Current Core Capabilities

* **Threat Knowledge Graph (Neo4j):** Stores MITRE ATT&CK entities (`intrusion-set`, `malware`, `tool`, `attack-pattern`, `campaign`) and typed relationships (`uses`, `subtechnique-of`, `attributed-to`).
* **Graph Query Service (`src/cybergraph/intelligence/queries.py`):** Supports health/statistics checks, entity search, actor profiling, and multi-hop neighborhood traversal.
* **REST API (`backend/api/main.py`):** FastAPI endpoints for `/health`, `/search`, `/entities/{key}`, and `/entities/{key}/relationships`.
* **Analyst Dashboard (`dashboard/app.py`):** Streamlit and Pyvis interface for searching entities, viewing threat actor profiles, and exploring graph neighborhoods.
* **Testing & CI (`tests/`, `.github/workflows/ci.yml`):** Unit tests with `pytest` and automated GitHub Actions test execution.
* **Deployment (`docker-compose.yml`, `backend/Dockerfile`, `dashboard/Dockerfile`, `render.yaml`):** Container and service deployment configurations.

## Research Direction

> *Can integrating heterogeneous cyber threat intelligence data into a knowledge graph improve threat relationship discovery and analyst investigation efficiency?*

Planned experimental tracks:

1. **Entity Recognition & Linking:** Extracting and linking threat entities and indicators from threat intelligence text.
2. **Graph-Based Relationship Analysis:** Exploring graph traversal and candidate relationships while keeping verified intelligence distinct from predicted relationships.
3. **Threat Intelligence Retrieval:** Evaluating retrieval performance (`Precision@K`, `Recall@K`, `F1`) for analyst investigations.

## Repository Structure

```text
CyberGraph/
|-- backend/
|   |-- api/
|   |-- services/
|   |-- schemas/
|   `-- Dockerfile
|-- src/cybergraph/
|   |-- ingestion/
|   |-- normalization/
|   |-- extraction/
|   |-- graph/
|   |-- intelligence/
|   |-- analysis/
|   `-- evaluation/
|-- dashboard/
|   |-- app.py
|   `-- Dockerfile
|-- scripts/
|   `-- download_data.py
|-- tests/
|-- .github/workflows/
|   `-- ci.yml
|-- pyproject.toml
|-- requirements.txt
|-- docker-compose.yml
`-- render.yaml

```

## Setup & Usage

### 1. Install Package and Dependencies

```bash
pip install -e .
pip install -r requirements.txt

```

### 2. Environment Configuration

Set the following environment variables (in `.env` or `.streamlit/secrets.toml`):

```env
NEO4J_URI=neo4j+s://<your-instance>.databases.neo4j.io
NEO4J_USER=neo4j
NEO4J_PASSWORD=<your-password>

```

### 3. Download MITRE ATT&CK Data

```bash
python scripts/download_data.py

```

### 4. Run Tests, API, and Dashboard

```bash
pytest tests/ -v
uvicorn backend.api.main:app --host 0.0.0.0 --port 8000
streamlit run dashboard/app.py

```

## Scope & Safety Note

This project is designed around passive, offline analysis of public threat intelligence datasets and sample data rather than active interaction with live adversary infrastructure.
