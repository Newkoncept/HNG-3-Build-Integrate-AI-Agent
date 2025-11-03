# HNG-3 — Build & Integrate AI Agent (Django + DRF + NVD + Telex)

A Django/DRF service that receives JSON-RPC 2.0 requests from a **Telex** agent, fetches device vulnerability data from the **NVD (National Vulnerability Database) API**, filters results to the **last 5 years**, sorts **newest → oldest**, and returns a clean **JSON-RPC 2.0** response for rendering in Telex.

> Repo: https://github.com/Newkoncept/HNG-3-Build-Integrate-AI-Agent

---

## ✨ Highlights

- **Django + DRF** endpoint with strict request validation
- **JSON-RPC 2.0** contract (request & response)
- **NVD API** integration for CVE lookup
- **Recent-only filtering** (last 5 years) and **latest-first sorting**
- Clear **error mapping** (validation, upstream/timeout, internal)
- Ready to plug into **@teleximapp** agents

---

## 🧭 Architecture

```
Telex Agent ──JSON-RPC──▶ Django/DRF endpoint
                     └──▶ Validate request (serializer)
                     └──▶ Call NVD API (requests)
                     └──▶ Filter (5y), sort (desc), shape result
◀── JSON-RPC result/error ── Return to Telex for display
```

**Key modules (expected):**
- `api/` — DRF view(s), serializers, URL routes
- `aiagent/` — agent/domain helpers (formatting, mapping, etc.)
- `manage.py`, `requirements.txt`

> Folder names above reflect the repo structure and can be adapted if different in your codebase.

---

## 🔌 Endpoint (example)

**URL:** `https://hng-3-build-integrate-ai-agent-production.up.railway.app/api/`  
**Method:** `POST`  
**Content-Type:** `application/json`

### Request (JSON-RPC 2.0)
```json
{
  "jsonrpc": "2.0",
  "id": "aaaaaaaaaaaaaaaaaaa4173c19",
  "method": "message/send",
  "params": {
    "message": {
      "kind": "message",
      "role": "user",
      "parts": [],
      "messageId": "be212121f999284784bf4ad622093f3cd95ce"
    }
  }
}

```

### Success Response (JSON-RPC 2.0)
```json
{
    "jsonrpc": "2.0",
    "id": "aaaaaaaaaaaaaaaaaaa4173c19",
    "result": {
        "id": "4217bfce-cfb0-43d6-b911-b5b11a6957a9",
        "contextId": "457e9e96-5c31-42f2-a35a-b31a320c0a3b",
        "status": {
            "state": "completed",
            "timestamp": "2025-11-03T23:05:26.402Z",
            "message": {
                "messageId": "1838f9fc-5932-4855-b61f-6c198227a619",
                "role": "agent",
                "parts": [
                    {
                        "kind": "text",
                        "text": "1 CVE-2025-41244\n• Severity: HIGH (7.8)\n• Published: 2025-09-29T17:15:30.843\n• Last Modified: 2025-11-03T19:15:53.027\n• Summary: VMware Aria Operations and VMware Tools contain a local privilege escalation vulnerability. A malicious local actor with non-administrative privileges having access to a VM with VMware Tools installed and managed by Aria Operations with SDMP enabled may exploit this vulnerability to escalate privileges to root on the same VM.\n\n\n"
                    }
                ],
                "kind": "message",
                "taskId": "090e5491-9716-48a9-ad06-dc8add6912b2"
            }
        },
        "artifacts": [
            {
                "artifactId": "4d5faced-a00d-4a82-9400-8da9e997a40e",
                "name": "deviceShield",
                "parts": [
                    {
                        "kind": "text",
                        "text": "1 CVE-2025-41244\n• Severity: HIGH (7.8)\n• Published: 2025-09-29T17:15:30.843\n• Last Modified: 2025-11-03T19:15:53.027\n• Summary: VMware Aria Operations and VMware Tools contain a local privilege escalation vulnerability. A malicious local actor with non-administrative privileges having access to a VM with VMware Tools installed and managed by Aria Operations with SDMP enabled may exploit this vulnerability to escalate privileges to root on the same VM.\n\n\n"
                    }
                ]
            }
        ],
        "history": [],
        "kind": "task"
    }
}
```

### Error Response (JSON-RPC 2.0)
```json
{
  "jsonrpc": "2.0",
  "id": "ab12",
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": {
      "params": {
        "device": "device must be a non-empty string"
      }
    }
  }
}
```

---

## ⚙️ Validation & Error Mapping

| Case | JSON-RPC code | HTTP status | Notes |
|---|---:|---:|---|
| Invalid request/params | `-32602` | `400` | JSON-RPC shape or `params.device` invalid |
| Upstream NVD error | `-32001` | `502` | Non-2xx response from NVD |
| NVD timeout | `-32002` | `504` | Request timed out |
| Internal error | `-32603` | `500` | Unhandled errors |

---

## 🌐 NVD API Usage

- Endpoint: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- Typical query parameters:
  - `keywordSearch=<device>` *(or migrate to CPE-based matching for precision)*
  - `pubStartDate=<ISO8601>` (UTC) — 5 years ago
  - `pubEndDate=<ISO8601>` (UTC) — now
  - `resultsPerPage=2000` *(paginate if needed)*
- Sort the returned list by `published` **descending**.
- Extract useful fields:
  - `cve.id`, `cve.published`, `cve.lastModified`
  - short description (`cve.descriptions[0].value`)
  - CVSS score (if present in `cve.metrics`)
  - reference URLs


---

## 🧪 Quick Start

### 1) Clone & install
```bash
git clone https://github.com/Newkoncept/HNG-3-Build-Integrate-AI-Agent.git
cd HNG-3-Build-Integrate-AI-Agent
python -m venv .venv && source .venv/bin/activate  # or venv\Scripts\activate on Windows
pip install --upgrade pip
pip install -r requirements.txt
```

### 2) Env vars
Create a `.env` (or export) with:
```
SECRET_KEY
```

### 3) Run
```bash
python manage.py migrate
python manage.py runserver 0.0.0.0:8000
```



---

## 🧰 Project Layout (example)

```
.
├── aiagent/
│   ├── __init__.py
│   └── urls.py               
│   └── settings.py               
├── api/
│   ├── __init__.py
│   └── utils.py               # date ranges, sorting, etc.
│   ├── views.py               # DRF view handling the endpoint
│   └── urls.py                # route definitions
├── manage.py
├── requirements.txt
└── README.md
```


---

## 🔒 Security Notes

- Treat `params.device` as **untrusted** input. Validate & normalize.
- Add **rate limiting** (e.g., DRF throttling) for public endpoints.
- Consider **caching** results per `(device, window)` to reduce latency and API calls.
- Avoid logging full payloads in production; sanitize PII if present.

---

## 🚀 Deployment Tips

- Use **Gunicorn**/**uvicorn** behind **Nginx** (or a PaaS: Render, Railway, Fly.io, etc.).
- Set strict timeouts for upstream NVD calls.
- Configure retries with jitter for transient failures.
- Monitor: request latency, error rate, NVD statuses, cache hit ratio.



---

## 🤝 Acknowledgements

- **Telex** (@teleximapp) for the agent platform
- **NVD** for the public CVE data
- **HNG** (@hnginternship) for the challenge prompt

---

## 🧑‍💻 Author
**Name:** Oluwagbemiga Taiwo
**Track:** Backend (Django) – HNG 13 Internship  
**GitHub:** [Newkoncept](https://github.com/Newkoncept)

---

## 🪪 License
MIT License © 2025 

---

## 📬 Contact

Open issues or reach out if you want help extending this service.
