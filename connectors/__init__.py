"""
Cloud & SAP connector stubs for the PoC.

In a real deployment these would call:
  - AWS Config / Security Hub / GuardDuty APIs
  - Azure Defender for Cloud + Purview
  - SAP Cloud ALM / BTP Audit Log / IAS

For the PoC we load static sample findings from data/findings.json.
"""

from pathlib import Path
import json

DATA = Path(__file__).resolve().parent.parent / "data" / "findings.json"


def fetch_all() -> dict:
    return json.loads(DATA.read_text())


def fetch_cloud(cloud: str) -> list:
    data = fetch_all()
    return data.get(cloud, [])
