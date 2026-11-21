"""CyberGraph Streamlit Dashboard.

Calistirma:
    streamlit run dashboard/app.py
"""

import os
import sys
from pathlib import Path

import streamlit as st
from pyvis.network import Network

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cybergraph.extraction.extractor import ThreatTextExtractor
from cybergraph.intelligence.investigation import ThreatInvestigationService
from cybergraph.intelligence.queries import GraphQueryService


@st.cache_resource
def get_service() -> GraphQueryService:
    """Servisi bir kez olustur, Streamlit oturumlari boyunca paylas."""
    try:
        uri = st.secrets["NEO4J_URI"]
        user = st.secrets["NEO4J_USER"]
        password = st.secrets["NEO4J_PASSWORD"]
    except Exception:
        uri = os.environ.get("NEO4J_URI", "")
        user = os.environ.get("NEO4J_USER", "")
        password = os.environ.get("NEO4J_PASSWORD", "")

    if not uri or not user or not password:
        st.error(
            "Neo4j baglanti bilgileri bulunamadi. "
            "Streamlit secrets veya ortam degiskenlerine "
            "NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD ekleyin."
        )
        st.stop()

    return GraphQueryService(uri, user, password)


@st.cache_resource
def get_extractor() -> ThreatTextExtractor:
    """Yerel STIX ornek verisi varsa sozluk cikariciyi yukler."""
    for candidate in (
        ROOT / "data/samples/attack_entities.json",
        ROOT / "data/samples/enterprise-attack.json",
    ):
        if candidate.exists():
            return ThreatTextExtractor.from_attack_json(candidate)
    return ThreatTextExtractor()


TYPE_COLORS = {
    "intrusion-set": "#e74c3c",
    "malware": "#e67e22",
    "tool": "#f1c40f",
    "attack-pattern": "#3498db",
    "campaign": "#9b59b6",
}


def render_graph(neighborhood: dict, height: int = 600) -> str:
    """Komsuluk verisinden pyvis HTML uret."""
    net = Network(height=f"{height}px", width="100%", bgcolor="#0e1117", font_color="white")
    net.barnes_hut(gravity=-8000, central_gravity=0.3, spring_length=200)

    for node in neighborhood["nodes"]:
        color = TYPE_COLORS.get(node["type"], "#95a5a6")
        net.add_node(
            node["key"],
            label=node.get("name") or node["key"],
            title=f"{node.get('name')} ({node['type']})",
            color=color,
        )

    for edge in neighborhood["edges"]:
        net.add_edge(edge["source"], edge["target"], title=edge["type"])

    return net.generate_html()


def merge_neighborhoods(
    query_svc: GraphQueryService, keys: list[str], depth: int = 1, max_nodes: int = 40
) -> dict:
    """Birden fazla eslesen dugumun komsuluk altgraflarini birlestirir."""
    merged_nodes: dict[str, dict] = {}
    merged_edges: list[dict] = []
    seen_edges: set[tuple] = set()

    for key in keys:
        nb = query_svc.get_neighborhood(key, depth=depth, max_nodes=max_nodes)
        for node in nb.get("nodes", []):
            merged_nodes[node["key"]] = node
        for edge in nb.get("edges", []):
            ekey = (edge["source"], edge["target"], edge["type"])
            if ekey not in seen_edges:
                seen_edges.add(ekey)
                merged_edges.append(edge)

    return {"nodes": list(merged_nodes.values()), "edges": merged_edges}


st.set_page_config(page_title="CyberGraph", page_icon="shield", layout="wide")
st.title("CyberGraph")
st.caption("AI-Driven Cyber Threat Intelligence and Knowledge Graph Platform")

svc = get_service()
health = svc.health()

col1, col2, col3 = st.columns(3)
col1.metric("Entities", f"{health['nodes']:,}")
col2.metric("Relationships", f"{health['relationships']:,}")
col3.metric("Status", health["status"])

st.divider()

tab_search, tab_actor, tab_graph, tab_investigate = st.tabs(
    ["Search", "Threat Actor Profile", "Graph Explorer", "Text Investigation"]
)

with tab_search:
    st.subheader("Search entities")
    query = st.text_input(
        "Search by name or ID (e.g. APT29, T1059, Emotet)",
        value="APT29",
    )
    if query:
        results = svc.search_entities(query, limit=20)
        if not results:
            st.info("No results.")
        else:
            for e in results:
                with st.expander(f"{e.name} ({e.key}) - {e.type}"):
                    if e.description:
                        st.write(e.description)
                    st.caption(f"Type: {e.type} | External ID: {e.external_id}")

with tab_actor:
    st.subheader("Threat actor profile")
    actor_key = st.text_input("Actor key (e.g. G0016 for APT29)", value="G0016")
    if actor_key:
        profile = svc.get_actor_profile(actor_key)
        if not profile:
            st.warning(f"Actor {actor_key} not found.")
        else:
            st.markdown(f"### {profile['actor']['name']}")
            if profile["actor"].get("description"):
                st.write(profile["actor"]["description"])
            st.caption(f"Total 'uses' relationships: {profile['total_uses']}")

            for typ, items in profile["uses_by_type"].items():
                with st.expander(f"{typ} ({len(items)})"):
                    for it in items:
                        st.write(f"- {it['name']} ({it['key']})")

            if profile["attributed_campaigns"]:
                with st.expander("Attributed campaigns"):
                    for c in profile["attributed_campaigns"]:
                        st.write(f"- {c['name']} ({c['key']})")

with tab_graph:
    st.subheader("Graph explorer")
    st.caption("Pick an entity and see its neighborhood up to N hops.")

    node_key = st.text_input("Entity key to explore", value="G0016")
    depth = st.slider("Depth (hops)", min_value=1, max_value=3, value=1)
    max_nodes = st.slider("Max nodes", min_value=20, max_value=200, value=50, step=10)

    if st.button("Explore") or node_key:
        if node_key:
            try:
                nb = svc.get_neighborhood(node_key, depth=depth, max_nodes=max_nodes)
            except Exception as exc:
                st.error(f"Query failed: {exc}")
            else:
                st.caption(f"{len(nb['nodes'])} nodes, {len(nb['edges'])} edges")
                if nb["nodes"]:
                    html = render_graph(nb)
                    st.components.v1.html(html, height=650, scrolling=True)
                else:
                    st.info("No neighborhood found.")

with tab_investigate:
    st.subheader("Text investigation & graph linking")
    st.caption("Extract IOCs/CVEs and ATT&CK entities from a report, then inspect linked graph context.")

    default_text = (
        "APT29 used Cobalt Strike and PowerShell while communicating with "
        "hxxp://malicious-domain[.]example[.]com and 185.220.101.4 (CVE-2023-23397)."
    )
    report_text = st.text_area("Threat report / analyst note", value=default_text, height=130)
    show_subgraph = st.checkbox("Render combined neighborhood graph for linked entities", value=True)

    if st.button("Investigate Text") and report_text.strip():
        inv_service = ThreatInvestigationService(extractor=get_extractor(), query_service=svc)
        report = inv_service.investigate_text(report_text)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Indicators / CVEs", report.summary["indicator_count"])
        m2.metric("Linked Graph Entities", report.summary["linked_entity_count"])
        m3.metric("Unmatched Mentions", report.summary["unmatched_mention_count"])
        m4.metric("IOC Chains", report.summary.get("chain_summary_count", len(report.chain_summaries)))

        if report.chain_summaries:
            st.markdown("#### Multi-Hop IOC Chain Summaries")
            for chain in report.chain_summaries:
                with st.expander(f"Indicator: {chain.anchor_name} ({chain.anchor_key})"):
                    st.write("**Related Malware:**", ", ".join(chain.related_malware) or "None")
                    st.write("**Related Actors:**", ", ".join(chain.related_actors) or "None")
                    st.write("**Related Techniques:**", ", ".join(chain.related_techniques) or "None")

        st.markdown("#### Extracted Indicators & Vulnerabilities")
        if report.indicators:
            for ind in report.indicators:
                st.write(f"- **{ind.entity_type}**: `{ind.normalized_value}` (confidence: {ind.confidence})")
        else:
            st.info("No indicators or CVEs extracted.")

        st.markdown("#### Linked ATT&CK Entities in Graph")
        if report.linked_entities:
            for item in report.linked_entities:
                with st.expander(
                    f"{item.name} ({item.key}) - {item.entity_type} | outgoing: {item.outgoing_count}"
                ):
                    st.caption(f"Matched text: `{item.matched_text}`")
                    if item.sample_targets:
                        st.write("Sample outgoing relations:", ", ".join(item.sample_targets))

            if show_subgraph:
                st.markdown("#### Linked Neighborhood Graph")
                linked_keys = [le.key for le in report.linked_entities]
                combined_nb = merge_neighborhoods(svc, linked_keys, depth=1, max_nodes=35)
                if combined_nb["nodes"]:
                    st.caption(f"{len(combined_nb['nodes'])} nodes, {len(combined_nb['edges'])} edges")
                    html = render_graph(combined_nb, height=520)
                    st.components.v1.html(html, height=550, scrolling=True)
        else:
            st.info("No ATT&CK entities linked in graph.")
