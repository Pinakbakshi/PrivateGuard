from __future__ import annotations
import json
import requests
import streamlit as st

st.set_page_config(page_title="PrivateGuard", page_icon="🛡️", layout="wide")
st.title("PrivateGuard")
st.caption("Local-first privacy scanner · encryption · audit verification")
api = st.sidebar.text_input("Local API URL", "http://127.0.0.1:8765")
tab_scan, tab_ops, tab_audit = st.tabs(["Directory scan", "Protect a file", "Audit integrity"])
with tab_scan:
    path = st.text_input("Directory to scan", placeholder="/Users/you/dev/project")
    if st.button("Scan directory", type="primary"):
        if not path: st.warning("Enter a directory path.")
        else:
            try:
                response = requests.post(f"{api}/scan", json={"path": path}, timeout=120)
                if response.ok:
                    data = response.json()
                    a,b,c = st.columns(3); a.metric("Files seen", data["files_seen"]); b.metric("Scanned", data["files_scanned"]); c.metric("Files with findings", data["files_with_findings"])
                    st.json(data)
                else: st.error(f"API returned {response.status_code}: {response.text}")
            except requests.RequestException as exc: st.error(f"Could not reach local API: {exc}")
with tab_ops:
    st.info("Sanitize creates a separate redacted copy. Encrypt creates a recoverable encrypted artifact. Outputs are never allowed to overwrite an existing file.")
    source = st.text_input("Source file")
    output = st.text_input("Output file path")
    left,right = st.columns(2)
    if left.button("Sanitize to output"):
        try:
            r = requests.post(f"{api}/sanitize", json={"path": source, "output_path": output}, timeout=60)
            st.success(r.json()) if r.ok else st.error(r.text)
        except requests.RequestException as exc: st.error(str(exc))
    if right.button("Encrypt to output"):
        try:
            r = requests.post(f"{api}/encrypt", json={"path": source, "output_path": output}, timeout=60)
            st.success(r.json()) if r.ok else st.error(r.text)
        except requests.RequestException as exc: st.error(str(exc))
with tab_audit:
    if st.button("Verify local audit chain"):
        try:
            r = requests.get(f"{api}/audit/verify", timeout=10)
            data = r.json(); st.success("Audit chain valid") if data.get("valid") else st.error("Audit chain verification failed")
            st.json(data)
        except requests.RequestException as exc: st.error(str(exc))
st.caption("Prototype warning: detection is heuristic. Do not expose the local API to an untrusted network.")
