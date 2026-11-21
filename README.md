
# CyberGraph

**AI-Driven Cyber Threat Intelligence and Knowledge Graph Platform**

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Streamlit-FF4B4B?style=flat-square&logo=streamlit)](https://utsamzxgrv8ftukzh2rtbt.streamlit.app)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python)](https://python.org)
[![Neo4j](https://img.shields.io/badge/Neo4j-AuraDB-008CC1?style=flat-square&logo=neo4j)](https://neo4j.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)

CyberGraph is an AI-driven platform that ingests heterogeneous cyber threat intelligence data, normalizes it, and builds a queryable **Knowledge Graph** to uncover relationships between threat actors, malware, attack techniques, and vulnerabilities.

Instead of listing isolated indicators, CyberGraph helps analysts answer questions like:
- *Which threat actors use this malware?*
- *What MITRE ATT&CK techniques are associated with this campaign?*
- *What is the full attack chain from an indicator to an actor?*

---

## Live Demo

Try it out: **[https://utsamzxgrv8ftukzh2rtbt.streamlit.app](https://utsamzxgrv8ftukzh2rtbt.streamlit.app)**

The demo is connected to a live Neo4j AuraDB instance containing **1,962 entities** and **19,482 relationships** from MITRE ATT&CK.

---

## Architecture

```text
Data Sources (MITRE ATT&CK STIX 2.1, CVE/NVD, IOC feeds)
        |
        v
Ingestion & Normalization (Python, Pydantic)
        |
        v
Knowledge Graph (Neo4j AuraDB)
        |
        v
Query Layer (Cypher, GraphQueryService)
        |
        +-- FastAPI backend (REST endpoints)
        +-- Streamlit dashboard (analyst UI)
```

---

## Features

- **Threat Knowledge Graph**: 1,900+ entities and 19,000+ relationships from MITRE ATT&CK.
- **Entity Search**: Fast search by name or external ID (e.g., `APT29`, `T1059`).
- **Threat Actor Profiles**: Aggregated view of malware, tools, and techniques used by each actor.
- **Graph Explorer**: N-hop neighborhood visualization with `pyvis`.
- **Cypher Query Service**: Reusable query layer shared between API and dashboard.
- **Cloud-Deployed**: Live demo on Streamlit Community Cloud.

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Python 3.10+ |
| Data Validation | Pydantic v2 |
| Graph Database | Neo4j AuraDB |
| Threat Intel Data | MITRE ATT&CK (STIX 2.1) |
| Query Layer | Cypher |
| Dashboard | Streamlit + pyvis |
| Backend (planned) | FastAPI |
| Testing (planned) | pytest |
| CI/CD | GitHub Actions |

---

## Repository Structure

```text
CyberGraph/
+-- dashboard/          # Streamlit UI
|   +-- app.py
+-- src/cybergraph/
|   +-- ingestion/      # Data download and parsing
|   +-- normalization/  # Entity normalization
|   +-- intelligence/   # Cypher query service
|   +-- extraction/     # NLP entity extraction (planned)
|   +-- analysis/       # Graph-based analysis (planned)
|   +-- evaluation/     # Benchmarking (planned)
+-- scripts/            # Utility scripts
|   +-- download_data.py
+-- tests/              # pytest test suite
+-- requirements.txt
+-- pyproject.toml
+-- README.md
```

---

## Getting Started

### 1. Clone and install

```bash
git clone https://github.com/almina-nur/CyberGraph-.git
cd CyberGraph-
pip install -r requirements.txt
```

### 2. Download data

```bash
python scripts/download_data.py
```

### 3. Configure Neo4j

Create a Neo4j AuraDB Free instance at [console.neo4j.io](https://console.neo4j.io).

Create a `.streamlit/secrets.toml` file:

```toml
NEO4J_URI = "neo4j+s://<your-instance>.databases.neo4j.io"
NEO4J_USER = "<your-instance-id>"
NEO4J_PASSWORD = "<your-password>"
```

### 4. Run dashboard

```bash
streamlit run dashboard/app.py
```

---

## Roadmap

- [x] MITRE ATT&CK STIX ingestion
- [x] Neo4j knowledge graph construction
- [x] Cypher query service
- [x] Streamlit dashboard (search, profiles, graph explorer)
- [ ] FastAPI REST backend
- [ ] Automated tests + CI/CD
- [ ] NLP-based entity extraction from threat reports
- [ ] Graph embeddings and link prediction
- [ ] React frontend (production UI)

---

## Data Source and License

- **MITRE ATT&CK**: Data is provided under the [MITRE ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/).
- **This project**: Code is released under the MIT License. See `LICENSE`.

---

## Author

**almina-nur** — [GitHub](https://github.com/almina-nur)

---

## Acknowledgments

- [MITRE ATT&CK](https://attack.mitre.org/) for the STIX 2.1 dataset.
- [Neo4j](https://neo4j.com/) for AuraDB Free tier.
- [Streamlit](https://streamlit.io/) for the community cloud hosting.
```
