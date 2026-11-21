"""CyberGraph Streamlit Dashboard.

Calistirma:
    streamlit run dashboard/app.py

Streamlit Cloud'da deploy edildiginde NEO4J_URI, NEO4J_USER,
NEO4J_PASSWORD ortam degiskenleri (secrets.toml) tanimli olmalidir.
"""

import os
import sys
from pathlib import Path

import streamlit as st
from pyvis.network import Network

# src/ paketini import edilebilir yap
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cybergraph.intelligence.queries import GraphQueryService


# ----- Baglanti -----

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


# ----- Yardimcilar -----

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

    # HTML'i string olarak dondur
    return net.generate_html()


# ----- Sayfa -----

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

tab_search, tab_actor, tab_graph = st.tabs(
    ["Search", "Threat Actor Profile", "Graph Explorer"]
)

# --- TAB 1: Arama ---
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

# --- TAB 2: Aktor Profili ---
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

# --- TAB 3: Graf Gezgini ---
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
                st.caption(
                    f"{len(nb['nodes'])} nodes, {len(nb['edges'])} edges"
                )
                if nb["nodes"]:
                    html = render_graph(nb)
                    st.components.v1.html(html, height=650, scrolling=True)
                else:
                    st.info("No neighborhood found.")
