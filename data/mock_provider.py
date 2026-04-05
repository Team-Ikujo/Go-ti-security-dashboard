"""
MockDataProvider — 기존 SQLite + 하드코딩 Mock 데이터 기반 구현체.
기존 db.py 및 review.py의 Mock 로직을 그대로 이식합니다.
"""
import time
import random
import math
from datetime import datetime, timedelta

import pandas as pd
import streamlit as st

from data.provider import DataProvider


class MockDataProvider(DataProvider):
    """Mock 데이터를 반환하는 개발용 DataProvider."""

    # ── 대시보드 상단 지표 카드 ──
    def get_dashboard_stats(self) -> dict:
        return {
            "total_access": 14859,
            "total_access_delta": "↑ +120",
            "total_access_badge": "badge-up",
            "unique_users": 6513,
            "unique_users_delta": "↓ -40",
            "unique_users_badge": "badge-down",
            "blocked_count": 8346,
            "blocked_delta": "↑ +500",
            "blocked_badge": "badge-up",
            "block_rate": 56.2,
            "block_rate_delta": "↑ 1.2%",
            "block_rate_badge": "badge-up",
        }

    # ── 탐지 이벤트 리스트 ──
    def get_enriched_history(self) -> pd.DataFrame:
        if "enriched_history" not in st.session_state:
            df_history = self._load_history_from_db()
            if df_history.empty:
                return df_history

            # 50개 데이터로 복제 (Mocking)
            df_expanded = pd.concat([df_history] * 17, ignore_index=True).head(50)

            df_display = df_expanded.copy()
            df_display["Event ID"] = ["#VZ" + str(1000 + i) for i in range(len(df_display))]
            target_urls = ["/login", "/checkout", "/event", "/signup", "/home"]
            df_display["Target URL"] = [target_urls[i % len(target_urls)] for i in range(len(df_display))]

            statuses = ["Blocked", "Pending", "Warning", "Passed"]
            df_display["Status"] = [statuses[i % len(statuses)] for i in range(len(df_display))]

            risk_scores = [94, 72, 88, 61, 45, 99]
            df_display["Risk Score"] = [risk_scores[i % len(risk_scores)] for i in range(len(df_display))]

            today = datetime.now().strftime("%Y-%m-%d")
            yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
            dates_pool = [today, today, today, yesterday, yesterday]
            df_display["접속일자"] = [random.choice(dates_pool) for _ in range(len(df_display))]

            baseball_games = {
                1: "2026 KBO 개막전 LG vs 삼성",
                2: "2026 KBO 정규시즌 KIA vs 한화",
                3: "2026 KBO 한국시리즈 7차전",
                4: "2026 KBO 올스타전 나눔 vs 드림"
            }
            game_ids_mock = [1, 1, 3, 2, 4, 1, 2]
            df_display["Game_ID"] = [game_ids_mock[i % len(game_ids_mock)] for i in range(len(df_display))]
            df_display["대상 경기"] = df_display["Game_ID"].map(lambda x: baseball_games.get(x, "알 수 없는 경기"))

            df_display = df_display[["Event ID", "접속일자", "접속시간", "대상 경기", "접속IP", "Target URL", "탐지유형", "Status", "Risk Score"]]

            st.session_state.enriched_history = df_display

        return st.session_state.enriched_history

    # ── OpenSearch 상세 분석 리포트 (Mock) ──
    def get_detection_report(self, event_id: str) -> dict:
        print(f"[MOCK] OpenSearch Report 조회: {event_id}")
        time.sleep(0.5)

        mock_db = {
            "#VZ1000": {
                "index": "macro-events-2026.03",
                "_id": "doc_vz1000",
                "threat_score": 94,
                "matched_rules": ["Mouse Linearity Threshold Exceeded", "Click Frequency High"],
                "raw_logs": {"click_rate": "15 cps", "mouse_variance": 0.001, "ip_reputation": "suspicious"}
            },
            "#VZ1001": {
                "index": "macro-events-2026.03",
                "_id": "doc_vz1001",
                "threat_score": 72,
                "matched_rules": ["API Abuse Detected", "Invalid User Agent"],
                "raw_logs": {"api_calls_per_sec": 50, "user_agent": "python-requests/2.31", "ip_reputation": "clean"}
            },
            "#VZ1002": {
                "index": "macro-events-2026.03",
                "_id": "doc_vz1002",
                "threat_score": 88,
                "matched_rules": ["Session Token Reused", "Simultaneous Login"],
                "raw_logs": {"active_sessions": 5, "geo_location": "Russia", "ip_reputation": "bad"}
            },
            "#VZ1003": {
                "index": "macro-events-2026.03",
                "_id": "doc_vz1003",
                "threat_score": 61,
                "matched_rules": ["Fast Checkout", "Bypass Captcha Time"],
                "raw_logs": {"checkout_duration_ms": 120, "captcha_solve_time": 0.1, "ip_reputation": "clean"}
            },
            "#VZ1004": {
                "index": "macro-events-2026.03",
                "_id": "doc_vz1004",
                "threat_score": 45,
                "matched_rules": ["Proxy IP Detected"],
                "raw_logs": {"proxy_type": "Data Center", "anonymity_level": "High", "ip_reputation": "warning"}
            }
        }

        default_mock = {
            "index": "macro-events-unknown",
            "_id": f"doc_{event_id.lower().replace('#', '')}",
            "threat_score": "N/A",
            "matched_rules": ["General Suspicious Behavior"],
            "raw_logs": {"detail": "No deep logs available for this generated ID."}
        }

        return mock_db.get(event_id, default_mock)

    # ── 수동 차단/통과 처리 (Mock) ──
    def update_event_status(self, event_id: str, new_status: str) -> bool:
        print(f"[MOCK] API Call — POST /api/v1/interventions/{event_id}/action -> {{'action': '{new_status}'}}")
        time.sleep(0.5)

        if "enriched_history" in st.session_state:
            df = st.session_state.enriched_history
            df.loc[df["Event ID"] == event_id, "Status"] = new_status
            st.session_state.enriched_history = df

        print(f"[MOCK] Event {event_id} status updated to {new_status}.")
        return True

    # ── 국가별 매크로 탐지 지도 데이터 ──
    def get_geo_detection_data(self) -> pd.DataFrame:
        return pd.DataFrame({
            'Country': ['Canada', 'Russia', 'Greenland', 'USA', 'China', 'Brazil', 'Australia', 'India', 'Japan', 'Korea'],
            'Lat': [56.13, 61.52, 71.7, 37.09, 35.86, -14.23, -25.27, 20.59, 35.6895, 37.5665],
            'Lon': [-106.34, 105.31, -42.6, -95.71, 104.19, -51.92, 133.77, 78.96, 139.6917, 126.9780],
            'Detections': [175, 162, 191, 220, 185, 145, 130, 110, 300, 700]
        })

    # ── 탐지 유형별 통계 (바 차트) ──
    def get_detection_type_stats(self) -> pd.DataFrame:
        return pd.DataFrame({
            "Type": ["Mouse Macro", "API Abuse", "Fast Click", "Proxy IP"],
            "Count": [240, 180, 140, 90]
        })

    # ── 가드레일 차단 이벤트 목록 (Mock) ──
    def get_guardrail_events(self) -> list[dict]:
        return [
            {
                "event_id"         : "GR-1001",
                "session_id"       : "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "user_id"          : "user_20482",
                "ip_address"       : "203.242.89.166",
                "risk_score"       : 0.97,
                "reason_codes"     : ["WEBDRIVER_DETECTED", "HEADLESS_BROWSER", "NO_PLUGINS"],
                "webdriver"        : True,
                "headless"         : True,
                "devtools_protocol": False,
                "plugins_count"    : 0,
                "languages_count"  : 1,
                "blocked_at"       : "2026-04-05T10:23:32+00:00",
                "status"           : "Blocked",
            },
            {
                "event_id"         : "GR-1002",
                "session_id"       : "b2c3d4e5-f6a7-8901-bcde-f12345678901",
                "user_id"          : "user_38871",
                "ip_address"       : "115.68.22.44",
                "risk_score"       : 0.88,
                "reason_codes"     : ["DEVTOOLS_PROTOCOL", "BHV_FAST_CLICK"],
                "webdriver"        : False,
                "headless"         : False,
                "devtools_protocol": True,
                "plugins_count"    : 2,
                "languages_count"  : 1,
                "blocked_at"       : "2026-04-05T10:41:15+00:00",
                "status"           : "Blocked",
            },
            {
                "event_id"         : "GR-1003",
                "session_id"       : "c3d4e5f6-a7b8-9012-cdef-123456789012",
                "user_id"          : None,
                "ip_address"       : "91.108.4.200",
                "risk_score"       : 0.73,
                "reason_codes"     : ["DATACENTER_IP", "BHV_RETRY_BURST"],
                "webdriver"        : False,
                "headless"         : False,
                "devtools_protocol": False,
                "plugins_count"    : 5,
                "languages_count"  : 2,
                "blocked_at"       : "2026-04-05T11:02:58+00:00",
                "status"           : "Pending",
            },
            {
                "event_id"         : "GR-1004",
                "session_id"       : "d4e5f6a7-b8c9-0123-defa-234567890123",
                "user_id"          : "user_55129",
                "ip_address"       : "58.229.10.83",
                "risk_score"       : 0.91,
                "reason_codes"     : ["WEBDRIVER_DETECTED", "PRECHECK_FAIL", "NO_PLUGINS"],
                "webdriver"        : True,
                "headless"         : False,
                "devtools_protocol": False,
                "plugins_count"    : 0,
                "languages_count"  : 1,
                "blocked_at"       : "2026-04-05T11:18:44+00:00",
                "status"           : "Blocked",
            },
            {
                "event_id"         : "GR-1005",
                "session_id"       : "e5f6a7b8-c9d0-1234-efab-345678901234",
                "user_id"          : "user_77340",
                "ip_address"       : "195.206.105.217",
                "risk_score"       : 0.62,
                "reason_codes"     : ["BLACKLIST_IP"],
                "webdriver"        : False,
                "headless"         : False,
                "devtools_protocol": False,
                "plugins_count"    : 8,
                "languages_count"  : 3,
                "blocked_at"       : "2026-04-05T11:35:07+00:00",
                "status"           : "Passed",
            },
        ]

    # ── 마우스 매크로 세션 목록 ──
    def get_mouse_macro_sessions(self) -> list[dict]:
        """마우스 서버에서 수신된 실제 세션 데이터를 반환합니다."""
        try:
            from utils.blocked_db import list_mouse_macro_sessions, init_blocked_db
            init_blocked_db()
            return list_mouse_macro_sessions()
        except Exception:
            return []

    # ── 내부 헬퍼: SQLite에서 기본 데이터 로드 ──
    @staticmethod
    def _load_history_from_db() -> pd.DataFrame:
        import sqlite3
        conn = sqlite3.connect('macro_history.db')
        df = pd.read_sql_query("SELECT * FROM history", conn)
        conn.close()
        return df
