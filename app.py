"""AgentSentinel dashboard (Person B).

This file only displays results. All model calls and evaluation logic live in
test_runner.py / model_client.py / evaluator.py (Person A).
"""
import json
from datetime import datetime

import streamlit as st

st.set_page_config(page_title="AgentSentinel", page_icon="🛡️", layout="wide")

STATUS_ICON = {"PASS": "🟢", "FAIL": "🔴", "ERROR": "🟠"}

st.title("🛡️ AgentSentinel")
st.caption("Security test harness for a local Hermes model running on Ollama.")
st.info(
    "Results are heuristic and depend on the model and version. A PASS means the "
    "response did not violate the test's explicit criteria. It does not prove "
    "the model is secure."
)

# Import the backend lazily so the UI can show a clear message if it isn't ready.
try:
    from test_runner import run_all_tests
except ImportError as exc:
    run_all_tests = None
    st.warning(f"Backend not available yet: {exc}")

if "results" not in st.session_state:
    st.session_state.results = []
    st.session_state.run_time = None

if st.button("▶ Run benchmark", type="primary", disabled=run_all_tests is None):
    with st.spinner("Running tests against the model... this can take a while."):
        try:
            st.session_state.results = run_all_tests()
            st.session_state.run_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        except Exception as exc:  # show runner failures instead of crashing the UI
            st.error(f"The test runner failed: {exc}")

results = st.session_state.results

if not results:
    st.write("No results yet. Click **Run benchmark** to start.")
    st.stop()

# ---- Summary ----
counts = {s: sum(1 for r in results if r.get("status") == s) for s in STATUS_ICON}
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total tests", len(results))
c2.metric("PASS", counts["PASS"])
c3.metric("FAIL", counts["FAIL"])
c4.metric("ERROR", counts["ERROR"])
if st.session_state.run_time:
    st.caption(f"Last run: {st.session_state.run_time}")

# ---- Export ----
report = {
    "generated_at": st.session_state.run_time,
    "summary": {"total": len(results), **counts},
    "results": results,
}
st.download_button(
    "⬇ Download JSON report",
    data=json.dumps(report, indent=2),
    file_name="agentsentinel_report.json",
    mime="application/json",
)

# ---- Filters ----
st.subheader("Results")
f1, f2 = st.columns(2)
status_filter = f1.multiselect("Status", list(STATUS_ICON), default=list(STATUS_ICON))
categories = sorted({r.get("category", "unknown") for r in results})
category_filter = f2.multiselect("Category", categories, default=categories)

shown = [
    r for r in results
    if r.get("status") in status_filter and r.get("category", "unknown") in category_filter
]

# ---- Table ----
st.dataframe(
    [
        {
            "ID": r.get("test_id"),
            "Status": f"{STATUS_ICON.get(r.get('status'), '')} {r.get('status')}",
            "Category": r.get("category"),
            "Name": r.get("name"),
            "Severity": r.get("severity"),
            "Finding": r.get("finding"),
        }
        for r in shown
    ],
    use_container_width=True,
    hide_index=True,
)

# ---- Detail view ----
st.subheader("Inspect responses")
for r in shown:
    label = f"{STATUS_ICON.get(r.get('status'), '')} {r.get('test_id')} — {r.get('name')}"
    with st.expander(label):
        st.write(f"**Category:** {r.get('category')}  |  **Severity:** {r.get('severity')}")
        st.write(f"**Finding:** {r.get('finding')}")
        st.text_area(
            "Model response",
            value=r.get("model_response", ""),
            height=150,
            disabled=True,
            key=f"resp_{r.get('test_id')}",
        )
