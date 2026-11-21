"""Tehdit metinlerinden IOC, CVE ve MITRE ATT&CK varliklari cikaran modul."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


@dataclass
class ExtractedEntity:
    """Metinden cikarilan ve normalize edilen varlik kaydi."""

    text: str
    normalized_value: str
    entity_type: str
    matched_key: Optional[str] = None
    source: str = "rule-lexicon-extractor"
    confidence: str = "medium"


IPV4_PATTERN = re.compile(
    r"""\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"""
)
CVE_PATTERN = re.compile(r"""\bCVE-\d{4}-\d{4,7}\b""", re.IGNORECASE)
SHA256_PATTERN = re.compile(r"""\b[a-fA-F0-9]{64}\b""")
SHA1_PATTERN = re.compile(r"""\b[a-fA-F0-9]{40}\b""")
MD5_PATTERN = re.compile(r"""\b[a-fA-F0-9]{32}\b""")
URL_PATTERN = re.compile(
    r"""\bhxxps?://[^\s\)"'>]+|\bhttps?://[^\s\)"'>]+""",
    re.IGNORECASE,
)
DOMAIN_PATTERN = re.compile(
    r"""\b(?:[a-zA-Z0-9-]+(?:\.|\[\.\]|\(\s*\.\s*\)))+[a-zA-Z]{2,}\b"""
)


def defang_text(text: str) -> str:
    """Guvenlik raporlarindaki defanged IOC ifadelerini standart bicime cevirir."""
    cleaned = text
    cleaned = re.sub(r"""\[\.\]|\(\s*\.\s*\)""", ".", cleaned)
    cleaned = re.sub(r"""^hxxp""", "http", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.replace("hxxp://", "http://").replace("hxxps://", "https://")
    return cleaned


class ThreatTextExtractor:
    """Kural tabanli IOC/CVE cikarimi ve MITRE ATT&CK sozluk eslestiricisi."""

    def __init__(self, attack_aliases: Optional[dict[str, tuple[str, str]]] = None) -> None:
        self.attack_aliases: dict[str, tuple[str, str]] = attack_aliases or {}

    @classmethod
    def from_attack_objects(cls, objects: Iterable[dict]) -> "ThreatTextExtractor":
        """STIX objelerinden sozluk kurar."""
        aliases: dict[str, tuple[str, str]] = {}
        target_types = {"intrusion-set", "malware", "tool", "attack-pattern", "campaign"}

        for obj in objects:
            obj_type = obj.get("type")
            if obj_type not in target_types:
                continue

            ext_refs = obj.get("external_references", [])
            ext_id = next(
                (r.get("external_id") for r in ext_refs if r.get("source_name") == "mitre-attack"),
                obj.get("id"),
            )
            if not ext_id:
                continue

            names: list[str] = []
            if obj.get("name"):
                names.append(obj["name"])
            for field in ("aliases", "x_mitre_aliases"):
                vals = obj.get(field) or []
                if isinstance(vals, list):
                    names.extend(str(v) for v in vals if v)

            noisy_single_tokens = {
                "tool",
                "net",
                "web",
                "app",
                "file",
                "data",
                "user",
                "admin",
                "scan",
                "test",
                "agent",
                "service",
                "system",
                "shell",
            }
            for raw_name in names:
                norm = " ".join(raw_name.strip().lower().split())
                if len(norm) < 4:
                    continue
                if " " not in norm and norm in noisy_single_tokens:
                    continue
                if norm not in aliases:
                    aliases[norm] = (ext_id, obj_type)

        return cls(attack_aliases=aliases)

    @classmethod
    def from_attack_json(cls, path: Path) -> "ThreatTextExtractor":
        """JSON dosyasindan yukler."""
        data = json.loads(path.read_text(encoding="utf-8"))
        objects = data["objects"] if isinstance(data, dict) and "objects" in data else data
        return cls.from_attack_objects(objects)

    def extract_indicators(self, text: str) -> list[ExtractedEntity]:
        """Metinden URL, domain, IPv4, CVE ve hash'leri cikarir."""
        normalized_text = defang_text(text)
        found: list[ExtractedEntity] = []
        seen: set[tuple[str, str]] = set()

        def add_item(raw: str, norm: str, etype: str, conf: str) -> None:
            key = (etype, norm.lower())
            if key not in seen:
                seen.add(key)
                found.append(
                    ExtractedEntity(
                        text=raw,
                        normalized_value=norm.upper() if etype == "vulnerability" else norm.lower(),
                        entity_type=etype,
                        matched_key=None,
                        source="regex-ioc-extractor",
                        confidence=conf,
                    )
                )

        for raw_url in URL_PATTERN.findall(text):
            add_item(raw_url, defang_text(raw_url), "url", "high")

        for raw_dom in DOMAIN_PATTERN.findall(normalized_text):
            dom_clean = raw_dom.strip(".").lower()
            if any(
                dom_clean.endswith(ext)
                for ext in (".exe", ".dll", ".ps1", ".bat", ".vbs", ".js", ".py")
            ):
                continue
            add_item(raw_dom, dom_clean, "domain", "medium")

        for raw_ip in IPV4_PATTERN.findall(normalized_text):
            add_item(raw_ip, raw_ip, "ipv4", "high")

        for raw_cve in CVE_PATTERN.findall(normalized_text):
            add_item(raw_cve, raw_cve.upper(), "vulnerability", "high")

        sha256_set = set(SHA256_PATTERN.findall(normalized_text))
        for h in sha256_set:
            add_item(h, h, "hash-sha256", "high")

        sha1_set = {
            h for h in SHA1_PATTERN.findall(normalized_text)
            if not any(h in s for s in sha256_set)
        }
        for h in sha1_set:
            add_item(h, h, "hash-sha1", "high")

        md5_set = {
            h for h in MD5_PATTERN.findall(normalized_text)
            if not any(h in s for s in sha256_set | sha1_set)
        }
        for h in md5_set:
            add_item(h, h, "hash-md5", "medium")

        return found

    def extract_attack_entities(self, text: str) -> list[ExtractedEntity]:
        """Bilinen MITRE ATT&CK ad ve alias sozlugune gore varlik eslestirir."""
        lower_text = defang_text(text).lower()
        matches: list[ExtractedEntity] = []
        seen_keys: set[tuple[str, str]] = set()

        for alias in sorted(self.attack_aliases.keys(), key=len, reverse=True):
            pattern = re.compile(
                r"""(?<![a-zA-Z0-9_-])""" + re.escape(alias) + r"""(?![a-zA-Z0-9_-])"""
            )
            if pattern.search(lower_text):
                ext_id, stix_type = self.attack_aliases[alias]
                dedup_key = (stix_type, ext_id)
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    matches.append(
                        ExtractedEntity(
                            text=alias,
                            normalized_value=alias,
                            entity_type=stix_type,
                            matched_key=ext_id,
                            source="mitre-lexicon-matcher",
                            confidence="medium",
                        )
                    )

        return matches

    def extract_all(self, text: str) -> dict[str, list[ExtractedEntity]]:
        """Hem IOC/CVE hem MITRE ATT&CK eslesmelerini bir arada dondurur."""
        return {
            "indicators": self.extract_indicators(text),
            "attack_entities": self.extract_attack_entities(text),
        }
