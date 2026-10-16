# API Rate Limiter & Security Gateway Proxy

An enterprise-grade, high-performance API Security Gateway built with **FastAPI** and **SQLite**. This microservice implements a strict **Sliding Window Log** algorithm to protect downstream backend routes from high-frequency traffic spikes, abusive consumers, and credential attacks.

Built following strict **Clean Architecture** patterns, this project features robust payload schema validation handlers, structured JSON logging, complete static type safety, and automated continuous integration quality gates.

---

## ✨ Features

- **Sliding Window Rate Limiter:** Stateful, rolling time-window restriction tracking using thread-safe `collections.deque` metrics maps.
- **SQLite Database Persistence:** Offloads authentication lookup streams onto an integrated local database system with atomic transactional support.
- **Graceful Error Schema Handlers:** Intercepts malformed inputs and exceptions natively to enforce consistent JSON API error patterns.
- **Embedded Administrative Panel:** Natively serves an interactive HTML control panel endpoint for API token management.
- **Rigorous Quality Pipelines:** Configured with robust `mypy` strict static types, `flake8` clean styles, and `pytest` execution tracking.

---

## 🏗️ Architectural Topology

```text
       Incoming HTTP Request
                 │
                 ▼
 ┌───────────────────────────────┐
 │     RateLimiterMiddleware     │
 ├───────────────────────────────┤
 │ 1. Extract 'X-API-Key' Header │
 │ 2. Query SQLite Key Status    │  ◄───►  [ SQLite Persistent Store ]
 │ 3. Process Sliding Window Log │         (gateway_control.db)
 └───────────────┬───────────────┘
                 │
        ┌────────┴────────┐
   Allowed (200 OK)  Blocked (429)
        │                 │
        ▼                 ▼
 ┌───────────────┐  ┌───────────────┐
 │ FastAPI Route │  │ JSON Response │
 └───────────────┘  └───────────────┘
```

---

## ⚙️ Project Directory Structure

```text
.
├── .github/
│   └── workflows/
│       └── test.yml         # Continuous Integration Quality Gate Configuration
├── src/
│   └── gateway/
│       ├── __init__.py
│       ├── database.py      # SQLite Persistence Driver Component
│       ├── main.py          # FastAPI Core Server Application Factory
│       ├── middleware/
│       │   ├── __init__.py
│       │   └── rate_limiter.py # Sliding Window Traffic Throttling Engine
│       └── templates/
│           └── dashboard.html  # Embedded Admin Panel Portal View
├── tests/
│   └── unit/
│       └── test_rate_limiter.py # Automated Test Suite Context 
├── pyproject.toml           # Unified Tool Configuration Manifesto
└── README.md                # System Documentation Manual
```

---

## 🚀 Getting Started

### 1. Prerequisites
Ensure you have **Python 3.11+** installed on your system.

### 2. Clone and Setup Environment
Clone the repository workspace layout and change into the root folder directory context:
```bash
git clone https://github.com
cd rate-limit-middleware
```

### 3. Install Dependencies
Install the package requirements and developer verification tool arrays in editable mode:
```bash
python -m pip install --upgrade pip
python -m pip install mypy flake8 pytest pytest-cov Flake8-pyproject httpx
python -m pip install -e .
```

### 4. Start the Application Server
Launch the gateway microservice interface locally using `uvicorn`:
```bash
uvicorn src.gateway.main:app --reload --host 127.0.0.1 --port 8000
```
On initialization, the storage engine will automatically bootstrap `gateway_control.db` and seed pre-configured authentication tokens.

---

## 🔍 API Interface Registry

| Endpoint | Method | Header Requirement | Description |
| :--- | :--- | :--- | :--- |
| `/api/v1/health` | `GET` | `X-API-Key: <token>` | Verifies gateway operational accessibility. |
| `/api/v1/keys/revoke` | `POST` | `X-API-Key: <token>` | Deactivates a targeted key account profile mapping inside SQLite. |
| `/dashboard` | `GET` | *None* | Exposes the visual management dashboard interface portal. |

---

## 🧪 Quality Gate Verification

The repository relies on strict configuration parameters defined inside `pyproject.toml`. To execute verification processes locally, run the target commands:

### Static Type Analysis (`mypy`)
```bash
mypy -m gateway
```

### Code Style Compliance (`flake8`)
```bash
flake8 src tests
```

### Automated Unit Testing & Coverage (`pytest`)
```bash
export PYTHONPATH=\$(pwd)/src
pytest --cov=gateway --cov-report=term-missing
```

---

## 📄 License

This software project architecture is released under the terms of the **MIT License**. For full parameter explanations, review the top-level repository licensing manifesto assets document.
