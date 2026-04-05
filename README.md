# AI-Powered Firewall Rule Optimizer

> An intelligent system that parses multi-vendor firewall rule sets, detects conflicts and redundancies using graph-based analysis, reorders rules using a machine learning model trained on traffic patterns, and exports a ranked audit report with actionable recommendations.

![CI](https://github.com/aditya-amrale/firewall_optimizer/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Tests](https://img.shields.io/badge/tests-124%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

- **Multi-format parser** — iptables-save, JSON/CSV, Cisco IOS ACL, AWS Security Groups
- **Conflict detection engine** — finds shadowed rules, contradictions, duplicates, and permissive catch-alls using an IP prefix trie and port interval tree
- **ML rule optimizer** — trains a Gradient Boosted Tree on traffic logs to reorder rules by predicted hit rate, with a policy-equivalence safety guarantee
- **Recommendation engine** — ranks findings by impact score (0–10) with concrete fix instructions and effort estimates
- **Multi-format export** — iptables-save, JSON, YAML, Markdown audit report, CSV
- **FastAPI backend** — REST API with file upload, Swagger UI at `/docs`
- **React dashboard** — live conflict graph, hit count heatmap, ML insights

---

## Project Structure

```
firewall_optimizer/
├── parser/                    # Phase 1 — Rule parsers
│   ├── models.py              # FirewallRule dataclass
│   ├── iptables_parser.py     # iptables-save format
│   ├── json_csv_parser.py     # JSON and CSV
│   ├── cisco_acl_parser.py    # Cisco IOS ACL
│   ├── aws_sg_parser.py       # AWS Security Groups
│   └── parser_facade.py       # Auto-detecting entry point
├── engine/                    # Phase 2 — Conflict detection
│   ├── ip_trie.py             # Binary prefix trie for subnet ops
│   ├── port_interval.py       # Port range overlap detection
│   └── conflict_engine.py     # Shadow / contradiction / duplicate / permissive
├── ml/                        # Phase 3 — ML optimization
│   ├── traffic_generator.py   # Synthetic traffic log generator
│   ├── feature_engineering.py # 20-feature extraction pipeline
│   └── rule_optimizer.py      # GBT model + policy-safe reordering
├── recommendation_engine.py   # Phase 4 — Ranked recommendations
├── exporter.py                # Phase 4 — iptables/JSON/YAML/MD/CSV export
├── pipeline.py                # Main orchestrator + CLI
├── api.py                     # Phase 6 — FastAPI backend
├── dashboard/                 # Phase 5 — React frontend
│   └── index.jsx
├── examples/                  # Sample rule files for testing
│   ├── sample_rules.iptables
│   ├── sample_rules.json
│   └── sample_cisco.txt
└── tests/                     # 124 unit tests
    ├── test_parsers.py
    ├── test_conflict_engine.py
    ├── test_recommendation_exporter.py
    └── test_ml_optimizer.py
```

---

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/aditya-amrale/firewall_optimizer.git
cd firewall_optimizer

python -m venv .venv
source .venv/bin/activate        # Mac/Linux
# .venv\Scripts\activate.bat     # Windows

pip install -r requirements.txt
```

### 2. Run the tests

```bash
pytest tests/test_parsers.py tests/test_conflict_engine.py tests/test_recommendation_exporter.py -v
# Expected: 124 passed
```

### 3. Analyze a rule file

```bash
# iptables format
python pipeline.py examples/sample_rules.iptables --output ./report

# JSON format
python pipeline.py examples/sample_rules.json --output ./report

# Cisco ACL
python pipeline.py examples/sample_cisco.txt --format cisco --output ./report

# With ML optimization (generates 2000 synthetic traffic records)
python pipeline.py examples/sample_rules.iptables --synthetic 2000 --output ./report
```

### 4. Start the API server

```bash
uvicorn api:app --reload --port 8000
# Open http://localhost:8000/docs for interactive Swagger UI
```

Upload a rule file via the `/api/analyze` endpoint and receive a full JSON audit report.

---

## CLI Reference

```
python pipeline.py <rules_file> [OPTIONS]

Arguments:
  rules_file          Path to firewall rule file (any supported format)

Options:
  --format TEXT       Force format: iptables | json | csv | cisco | aws
  --traffic TEXT      Path to real traffic log CSV
  --synthetic INT     Generate N synthetic traffic records for ML training
  --output TEXT       Output directory for reports (default: ./output)
  --quiet             Suppress progress output
```

---

## Conflict Detection

The engine detects four categories of issues in any rule set:

| Type | Description | Severity |
|---|---|---|
| **Contradiction** | Opposite actions on overlapping traffic — policy outcome depends on rule order | Critical |
| **Shadow** | Rule B is dead code because Rule A (higher priority) matches every packet B would match | High |
| **Permissive** | Catch-all ALLOW on 0.0.0.0/0 with no port/protocol restriction | Medium |
| **Duplicate** | Two rules with identical match conditions and action | Medium |
| **Redundant** | Rule whose removal doesn't change the policy outcome | Low |

---

## Supported Formats

| Format | Example file | Auto-detected? |
|---|---|---|
| iptables-save | `iptables-save > rules.iptables` | Yes (by `-A` pattern) |
| JSON | `rules.json` | Yes (by `[` or `{`) |
| CSV | `rules.csv` | Yes (by header row) |
| Cisco IOS ACL | `acl.txt` | Yes (by `ip access-list`) |
| AWS Security Groups | `sg.json` | Yes (by `SecurityGroups` key) |

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/analyze` | Upload rule file, get full report |
| `GET` | `/api/reports` | List all cached report IDs |
| `GET` | `/api/report/{id}` | Fetch a cached report |
| `GET` | `/api/report/{id}/download/{fmt}` | Download export file |
| `GET` | `/docs` | Interactive Swagger UI |

---

## ML Optimizer

The ML optimizer uses a `GradientBoostingRegressor` trained on 20 features per rule:

- **Traffic-derived**: hit count, bytes matched, hit rate percentage
- **Rule intrinsic**: specificity score, IP prefix lengths, port range width, port category
- **Positional**: current priority rank, position in chain

Rules are reordered by predicted hit rate to minimize average packet evaluation steps. A **topological sort with safety constraints** ensures rules with opposite actions on overlapping traffic are never swapped — preserving policy equivalence.

---

## AWS Deployment

```bash
# On EC2 (Ubuntu 22.04, t2.micro free tier)
git clone https://github.com/aditya-amrale/firewall_optimizer.git
cd firewall_optimizer
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn api:app --host 0.0.0.0 --port 8000
```

Access the API at `http://YOUR_EC2_PUBLIC_IP:8000/docs`

---

## Running Tests

```bash
# All core tests
pytest tests/test_parsers.py tests/test_conflict_engine.py tests/test_recommendation_exporter.py -v

# With coverage
pytest tests/ --cov=. --cov-report=html

# Specific module
pytest tests/test_conflict_engine.py -v -k "contradiction"
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| ML | scikit-learn (GradientBoostingRegressor), numpy |
| API | FastAPI, uvicorn |
| Frontend | React 18, D3.js, Recharts |
| Testing | pytest, Hypothesis |
| CI | GitHub Actions |
| Deployment | AWS EC2, S3, CloudFront |

---

## Academic Context

This project was developed as an academic cybersecurity project demonstrating:
- Custom data structure design (IP prefix trie, port interval tree)
- ML applied to network security (rule ranking via GBT)
- Policy-safe algorithmic reordering (topological sort with conflict constraints)
- Multi-format parsing with a unified data model

---

## License

MIT License — see [LICENSE](LICENSE) for details.