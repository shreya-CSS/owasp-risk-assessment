"""Registry of navigation pages (filled by app.py) so pages can link to each other."""
from __future__ import annotations

import streamlit as st

PAGES: dict = {}  # url_path -> StreamlitPage


def go(name: str) -> None:
    st.switch_page(PAGES[name])
