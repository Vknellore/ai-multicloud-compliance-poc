# AI-Powered Secure Multi-Cloud Compliance Platform — PoC

> **Scope:** AWS · Microsoft Azure · SAP

Lightweight proof-of-concept control plane for continuous compliance across AWS, Azure, and SAP landscapes.

## Features

| Capability | Implementation |
|---|---|
| Multi-cloud + SAP findings | Sample findings for AWS, Azure, SAP |
| Risk prioritization | Heuristic AI scoring (severity × criticality × exposure) |
| Natural-language explanation | Generated risk narrative + business impact |
| Remediation guidance | Steps + optional Terraform snippets |
| Unified dashboard | Dark-themed web UI with filters |
| REST API | `/api/findings`, `/api/stats`, `/api/remediate` |
| Evidence simulation | Remediation log as evidence trail |

> Demo only — connectors are stubs; AI is rule-based (swap for Bedrock / Azure OpenAI).

## Quick start

```bash
git clone https://github.com/Vknellore/ai-multicloud-compliance-poc.git
cd ai-multicloud-compliance-poc
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Open **http://localhost:8000** · API docs **http://localhost:8000/docs**

## API examples

```bash
curl http://localhost:8000/api/health
curl http://localhost:8000/api/stats
curl "http://localhost:8000/api/findings?cloud=sap"
curl -X POST http://localhost:8000/api/remediate \
  -H "Content-Type: application/json" \
  -d '{"finding_id":"aws-001","approved_by":"alice"}'
```

## Project layout

```
├── app/main.py           # FastAPI app, risk engine, API, dashboard
├── connectors/           # Stub connectors (replace with real SDKs)
├── data/findings.json    # Sample AWS / Azure / SAP findings
├── templates/            # Dashboard HTML
├── requirements.txt
└── README.md
```

## Roadmap to production

1. Live connectors: AWS Config / Security Hub, Azure Defender, SAP Cloud ALM / BTP
2. LLM risk engine (Bedrock / Azure OpenAI) + RAG over control catalogs
3. Policy-as-Code (OPA/Rego)
4. Immutable evidence store with cryptographic hashes
5. ServiceNow / Jira + SIEM integration
6. Least-privilege IAM and private endpoints for the control plane

## License

PoC / internal demonstration only.
