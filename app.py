import streamlit as st
import pandas as pd
import plotly.express as px
from openai import OpenAI
from streamlit_cognito_auth import CognitoAuthenticator
import sqlite3  # DB 연동 예시
import requests  # Grafana API 연동
from datetime import datetime, timedelta
import base64  # Basic Auth 인증용
import urllib3  # SSL 경고 억제
import threading


@st.cache_resource
def _start_api_server():
    """FastAPI 수신 서버를 백그라운드 스레드로 실행합니다 (포트 8100)."""
    import uvicorn
    from server import app as fastapi_app
    thread = threading.Thread(
        target=lambda: uvicorn.run(fastapi_app, host="0.0.0.0", port=8100, log_level="warning"),
        daemon=True,
    )
    thread.start()
    return thread


_start_api_server()

# 앱 최상단에 배치

st.markdown(
    """
    <style>
    ._profileContainer_gzau3_53, ._link_gzau3_10 {
        visibility: hidden !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# if not hasattr(st, "experimental_rerun"):
#     st.experimental_rerun = st.rerun

# # SSL 경고 억제 (개발 환경 자체 서명 인증서 사용 시)
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# MUST be first streamit command
st.set_page_config(page_title="Go-Ti Security Admin", layout="wide")

from utils.db import init_db
from utils.config import is_mock_mode
from utils.auth import init_auth
from utils.session import init_agent_sessions

from components.css_overrides import inject_custom_css
from components.sidebar import render_sidebar
from views.dashboard import render_dashboard
from views.agent import render_agent
from views.review import render_review
from views.grafana import render_grafana

# 앱 최상단에 CSS 레이아웃 주입
inject_custom_css()

# 앱 시작 시 DB 상태 초기화 (Mock 모드에서만)
if is_mock_mode():
    init_db()

# 에이전트 다중 세션 스토어 초기화
init_agent_sessions()

# 기본 현재 네비게이션 메뉴 상태 선언
if "current_menu" not in st.session_state:
    st.session_state.current_menu = "실시간 매크로 모니터링"

# 로그인 / 인증 확인 (테스트 모드 처리 포함)
is_logged_in = init_auth()

if not is_logged_in:
    # 로그인 실패 시 혹은 화면 진입 통제
    st.stop()

# 인증된 유저라면 사이드바 렌더링 호출
render_sidebar()

# 화면 라우팅 (current_menu 스테이트 기준)
menu_selection = st.session_state.current_menu

if menu_selection == "실시간 매크로 모니터링":
    render_dashboard()
elif menu_selection == "AI 방어 어시스턴스 에이전트":
    render_agent()
elif menu_selection == "의심 유저 수동 심사":
    render_review()
elif menu_selection == "Grafana":
    render_grafana()
