"""MITRE ATT&CK verisini indirir. Kullanim: python scripts/download_data.py"""
import json
import sys
from pathlib import Path

import requests

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)
DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "samples"


def download_attack() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    target = DATA_DIR / "enterprise-attack.json"
    if target.exists():
        print(f"Zaten mevcut: {target}")
        return
    print(f"Indiriliyor: {ATTACK_URL}")
    r = requests.get(ATTACK_URL, timeout=180)
    r.raise_for_status()
    target.write_bytes(r.content)
    print(f"Kaydedildi: {target} ({target.stat().st_size / 1e6:.1f} MB)")


def extract_entities() -> None:
    src = DATA_DIR / "enterprise-attack.json"
    if not src.exists():
        print("Once ATT&CK verisini indir.")
        sys.exit(1)
    data = json.loads(src.read_text())
    types = {"intrusion-set", "malware", "attack-pattern", "tool", "campaign"}
    entities = [o for o in data["objects"] if o["type"] in types]
    out = DATA_DIR / "attack_entities.json"
    out.write_text(json.dumps(entities, indent=2))
    print(f"{len(entities)} varlik kaydedildi: {out}")


if __name__ == "__main__":
    download_attack()
    extract_entities()
