"""
MockDataProvider — 완전 하드코딩 Mock 데이터 기반 구현체.
SQLite 의존 없이 대시보드 전체 섹션에 풍부한 더미 데이터를 제공합니다.
"""
import time
import random
from datetime import datetime, timedelta

import pandas as pd
import streamlit as st

from data.provider import DataProvider


class MockDataProvider(DataProvider):
    """Mock 데이터를 반환하는 개발용 DataProvider."""

    # ── 대시보드 상단 지표 카드 ──
    def get_dashboard_stats(self) -> dict:
        return {
            "total_access"      : 21_473,
            "total_access_delta": "↑ +1,842",
            "total_access_badge": "badge-up",
            "unique_users"      : 9_218,
            "unique_users_delta": "↓ -312",
            "unique_users_badge": "badge-down",
            "blocked_count"     : 11_905,
            "blocked_delta"     : "↑ +983",
            "blocked_badge"     : "badge-up",
            "block_rate"        : 55.4,
            "block_rate_delta"  : "↑ 2.1%",
            "block_rate_badge"  : "badge-up",
        }

    # ── 탐지 이벤트 리스트 ──
    def get_enriched_history(self) -> pd.DataFrame:
        if "enriched_history" not in st.session_state:
            st.session_state.enriched_history = self._build_enriched_history()
        return st.session_state.enriched_history

    @staticmethod
    def _build_enriched_history() -> pd.DataFrame:
        games = {
            1: "2026 KBO 개막전 LG vs 삼성",
            2: "2026 KBO 정규시즌 KIA vs 한화",
            3: "2026 KBO 한국시리즈 7차전",
            4: "2026 KBO 올스타전 나눔 vs 드림",
            5: "2026 KBO 정규시즌 두산 vs NC",
            6: "2026 KBO 준플레이오프 롯데 vs kt",
        }
        ips = [
            "203.242.89.166", "218.234.23.186", "112.111.22.33", "91.108.4.200",
            "58.229.10.83",   "195.206.105.217","115.68.22.44",  "1.234.56.78",
            "103.45.67.89",   "175.200.45.12",  "210.123.45.67", "61.77.88.99",
            "45.33.32.156",   "185.220.101.33", "159.89.123.45", "104.21.67.89",
            "172.67.45.123",  "134.209.88.11",  "167.71.55.200", "95.216.44.77",
        ]
        urls = ["/login", "/checkout", "/event", "/signup", "/home",
                "/ticket/buy", "/mypage", "/api/seats", "/payment", "/schedule"]
        types = ["동적 행위분석", "정적 통계분석", "LLM 심층분석", "블랙리스트", "동적 행위분석"]
        statuses = ["Blocked", "Blocked", "Blocked", "Pending", "Warning", "Passed"]
        risk_pool = [97, 94, 91, 88, 85, 82, 79, 75, 72, 68, 61, 55, 45, 38]

        today     = datetime.now().strftime("%Y-%m-%d")
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        two_days  = (datetime.now() - timedelta(days=2)).strftime("%Y-%m-%d")
        dates_pool = [today]*5 + [yesterday]*3 + [two_days]*2

        rows = []
        rng  = random.Random(42)
        for i in range(60):
            h = rng.randint(9, 23)
            m = rng.randint(0, 59)
            s = rng.randint(0, 59)
            rows.append({
                "Event ID"  : f"#VZ{1000 + i}",
                "접속일자"   : rng.choice(dates_pool),
                "접속시간"   : f"{h:02d}:{m:02d}:{s:02d}",
                "대상 경기"  : games[rng.randint(1, 6)],
                "접속IP"     : rng.choice(ips),
                "Target URL" : rng.choice(urls),
                "탐지유형"   : rng.choice(types),
                "Status"     : rng.choice(statuses),
                "Risk Score" : rng.choice(risk_pool),
            })

        return pd.DataFrame(rows)

    # ── OpenSearch 상세 분석 리포트 (Mock) ──
    def get_detection_report(self, event_id: str) -> dict:
        time.sleep(0.3)
        mock_db = {
            "#VZ1000": {
                "index": "macro-events-2026.04", "_id": "doc_vz1000",
                "threat_score": 97,
                "matched_rules": ["Mouse Linearity Exceeded", "Click Freq High", "Webdriver Detected"],
                "raw_logs": {"click_rate": "18 cps", "mouse_variance": 0.0008, "ip_reputation": "suspicious"},
            },
            "#VZ1001": {
                "index": "macro-events-2026.04", "_id": "doc_vz1001",
                "threat_score": 94,
                "matched_rules": ["API Abuse Detected", "Invalid User Agent"],
                "raw_logs": {"api_calls_per_sec": 55, "user_agent": "python-requests/2.31", "ip_reputation": "clean"},
            },
            "#VZ1002": {
                "index": "macro-events-2026.04", "_id": "doc_vz1002",
                "threat_score": 88,
                "matched_rules": ["Session Token Reused", "Simultaneous Login"],
                "raw_logs": {"active_sessions": 7, "geo_location": "Russia", "ip_reputation": "bad"},
            },
            "#VZ1003": {
                "index": "macro-events-2026.04", "_id": "doc_vz1003",
                "threat_score": 82,
                "matched_rules": ["Fast Checkout", "Bypass Captcha Time"],
                "raw_logs": {"checkout_duration_ms": 90, "captcha_solve_time": 0.05, "ip_reputation": "clean"},
            },
            "#VZ1004": {
                "index": "macro-events-2026.04", "_id": "doc_vz1004",
                "threat_score": 61,
                "matched_rules": ["Proxy IP Detected"],
                "raw_logs": {"proxy_type": "Data Center", "anonymity_level": "High", "ip_reputation": "warning"},
            },
        }
        default = {
            "index": "macro-events-2026.04",
            "_id": f"doc_{event_id.lower().replace('#', '')}",
            "threat_score": "N/A",
            "matched_rules": ["General Suspicious Behavior"],
            "raw_logs": {"detail": "No deep logs available for this ID."},
        }
        return mock_db.get(event_id, default)

    # ── 수동 차단/통과 처리 (Mock) ──
    def update_event_status(self, event_id: str, new_status: str) -> bool:
        time.sleep(0.3)
        if "enriched_history" in st.session_state:
            df = st.session_state.enriched_history
            df.loc[df["Event ID"] == event_id, "Status"] = new_status
            st.session_state.enriched_history = df
        return True

    # ── 국가별 매크로 탐지 지도 데이터 ──
    def get_geo_detection_data(self) -> pd.DataFrame:
        return pd.DataFrame({
            "Country"   : ["Korea"],
            "Lat"       : [37.5665],
            "Lon"       : [126.978],
            "Detections": [1_820],
        })

    # ── 탐지 유형별 통계 (바 차트) ──
    def get_detection_type_stats(self) -> pd.DataFrame:
        return pd.DataFrame({
            "Type" : ["Mouse Macro", "API Abuse", "Fast Click", "Proxy IP",
                      "Headless Browser", "Credential Stuffing"],
            "Count": [520, 310, 275, 190, 160, 95],
        })

    # ── 가드레일 차단 이벤트 목록 (실제 DB + Mock 폴백) ──
    def get_guardrail_events(self) -> list[dict]:
        # 실제 가드레일 서버에서 수신된 이벤트가 있으면 우선 표시
        try:
            from utils.blocked_db import list_blocked_events, init_blocked_db
            init_blocked_db()
            real_events = list_blocked_events()
            if real_events:
                return real_events
        except Exception:
            pass
        # 실제 데이터 없으면 Mock 폴백
        return [
            {
                "event_id": "GR-1001", "session_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "user_id": "user_20482", "ip_address": "203.242.89.166",
                "risk_score": 0.97,
                "reason_codes": ["WEBDRIVER_DETECTED", "HEADLESS_BROWSER", "NO_PLUGINS"],
                "webdriver": True, "headless": True, "devtools_protocol": False,
                "plugins_count": 0, "languages_count": 1,
                "blocked_at": "2026-04-15T09:11:22+00:00", "status": "Blocked",
            },
            {
                "event_id": "GR-1002", "session_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
                "user_id": "user_38871", "ip_address": "115.68.22.44",
                "risk_score": 0.91,
                "reason_codes": ["DEVTOOLS_PROTOCOL", "BHV_FAST_CLICK"],
                "webdriver": False, "headless": False, "devtools_protocol": True,
                "plugins_count": 2, "languages_count": 1,
                "blocked_at": "2026-04-15T09:28:05+00:00", "status": "Blocked",
            },
            {
                "event_id": "GR-1003", "session_id": "c3d4e5f6-a7b8-9012-cdef-123456789012",
                "user_id": None, "ip_address": "91.108.4.200",
                "risk_score": 0.85,
                "reason_codes": ["DATACENTER_IP", "BHV_RETRY_BURST"],
                "webdriver": False, "headless": False, "devtools_protocol": False,
                "plugins_count": 5, "languages_count": 2,
                "blocked_at": "2026-04-15T09:44:51+00:00", "status": "Pending",
            },
            {
                "event_id": "GR-1004", "session_id": "d4e5f6a7-b8c9-0123-defa-234567890123",
                "user_id": "user_55129", "ip_address": "58.229.10.83",
                "risk_score": 0.93,
                "reason_codes": ["WEBDRIVER_DETECTED", "PRECHECK_FAIL", "NO_PLUGINS"],
                "webdriver": True, "headless": False, "devtools_protocol": False,
                "plugins_count": 0, "languages_count": 1,
                "blocked_at": "2026-04-15T10:02:37+00:00", "status": "Blocked",
            },
            {
                "event_id": "GR-1005", "session_id": "e5f6a7b8-c9d0-1234-efab-345678901234",
                "user_id": "user_77340", "ip_address": "195.206.105.217",
                "risk_score": 0.62,
                "reason_codes": ["BLACKLIST_IP"],
                "webdriver": False, "headless": False, "devtools_protocol": False,
                "plugins_count": 8, "languages_count": 3,
                "blocked_at": "2026-04-15T10:19:14+00:00", "status": "Passed",
            },
            {
                "event_id": "GR-1006", "session_id": "f6a7b8c9-d0e1-2345-fabc-456789012345",
                "user_id": "user_13024", "ip_address": "45.33.32.156",
                "risk_score": 0.88,
                "reason_codes": ["HEADLESS_BROWSER", "BHV_FAST_CLICK", "NO_PLUGINS"],
                "webdriver": False, "headless": True, "devtools_protocol": False,
                "plugins_count": 0, "languages_count": 1,
                "blocked_at": "2026-04-15T10:35:02+00:00", "status": "Blocked",
            },
            {
                "event_id": "GR-1007", "session_id": "07b8c9d0-e1f2-3456-abcd-567890123456",
                "user_id": "user_62801", "ip_address": "185.220.101.33",
                "risk_score": 0.79,
                "reason_codes": ["DATACENTER_IP", "BHV_LINEAR_MOUSE"],
                "webdriver": False, "headless": False, "devtools_protocol": False,
                "plugins_count": 3, "languages_count": 1,
                "blocked_at": "2026-04-15T10:51:48+00:00", "status": "Blocked",
            },
            {
                "event_id": "GR-1008", "session_id": "18c9d0e1-f2a3-4567-bcde-678901234567",
                "user_id": None, "ip_address": "159.89.123.45",
                "risk_score": 0.95,
                "reason_codes": ["WEBDRIVER_DETECTED", "DEVTOOLS_PROTOCOL", "HEADLESS_BROWSER"],
                "webdriver": True, "headless": True, "devtools_protocol": True,
                "plugins_count": 0, "languages_count": 1,
                "blocked_at": "2026-04-15T11:07:33+00:00", "status": "Blocked",
            },
            {
                "event_id": "GR-1009", "session_id": "29d0e1f2-a3b4-5678-cdef-789012345678",
                "user_id": "user_49037", "ip_address": "104.21.67.89",
                "risk_score": 0.71,
                "reason_codes": ["BHV_RETRY_BURST", "PRECHECK_FAIL"],
                "webdriver": False, "headless": False, "devtools_protocol": False,
                "plugins_count": 6, "languages_count": 2,
                "blocked_at": "2026-04-15T11:24:19+00:00", "status": "Pending",
            },
            {
                "event_id": "GR-1010", "session_id": "3ae1f2a3-b4c5-6789-defa-890123456789",
                "user_id": "user_81453", "ip_address": "172.67.45.123",
                "risk_score": 0.83,
                "reason_codes": ["CREDENTIAL_STUFFING", "BHV_FAST_CLICK"],
                "webdriver": False, "headless": False, "devtools_protocol": False,
                "plugins_count": 4, "languages_count": 2,
                "blocked_at": "2026-04-15T11:40:55+00:00", "status": "Blocked",
            },
            {
                "event_id": "GR-1011", "session_id": "4bf2a3b4-c5d6-7890-efab-901234567890",
                "user_id": "user_30276", "ip_address": "134.209.88.11",
                "risk_score": 0.68,
                "reason_codes": ["BLACKLIST_IP", "DATACENTER_IP"],
                "webdriver": False, "headless": False, "devtools_protocol": False,
                "plugins_count": 7, "languages_count": 3,
                "blocked_at": "2026-04-15T11:57:41+00:00", "status": "Blocked",
            },
            {
                "event_id": "GR-1012", "session_id": "5ca3b4c5-d6e7-8901-fabc-012345678901",
                "user_id": "user_97614", "ip_address": "167.71.55.200",
                "risk_score": 0.99,
                "reason_codes": ["WEBDRIVER_DETECTED", "HEADLESS_BROWSER", "DEVTOOLS_PROTOCOL", "NO_PLUGINS"],
                "webdriver": True, "headless": True, "devtools_protocol": True,
                "plugins_count": 0, "languages_count": 1,
                "blocked_at": "2026-04-15T12:13:08+00:00", "status": "Blocked",
            },
            {
                "event_id": "GR-1013", "session_id": "6db4c5d6-e7f8-9012-abcd-123456789012",
                "user_id": None, "ip_address": "95.216.44.77",
                "risk_score": 0.76,
                "reason_codes": ["BHV_LINEAR_MOUSE", "BHV_FAST_CLICK"],
                "webdriver": False, "headless": False, "devtools_protocol": False,
                "plugins_count": 2, "languages_count": 1,
                "blocked_at": "2026-04-15T12:29:54+00:00", "status": "Pending",
            },
            {
                "event_id": "GR-1014", "session_id": "7ec5d6e7-f8a9-0123-bcde-234567890123",
                "user_id": "user_53892", "ip_address": "1.234.56.78",
                "risk_score": 0.57,
                "reason_codes": ["PRECHECK_FAIL"],
                "webdriver": False, "headless": False, "devtools_protocol": False,
                "plugins_count": 9, "languages_count": 4,
                "blocked_at": "2026-04-15T12:46:30+00:00", "status": "Passed",
            },
            {
                "event_id": "GR-1015", "session_id": "8fd6e7f8-a9b0-1234-cdef-345678901234",
                "user_id": "user_18745", "ip_address": "103.45.67.89",
                "risk_score": 0.90,
                "reason_codes": ["WEBDRIVER_DETECTED", "BHV_RETRY_BURST"],
                "webdriver": True, "headless": False, "devtools_protocol": False,
                "plugins_count": 1, "languages_count": 1,
                "blocked_at": "2026-04-15T13:03:17+00:00", "status": "Blocked",
            },
        ]

    # ── 마우스 매크로 세션 목록 (실제 DB + Mock 폴백) ──
    def get_mouse_macro_sessions(self) -> list[dict]:
        """실제 DB에 세션이 있으면 그것을 반환하고, 없으면 Mock 데이터를 반환합니다."""
        try:
            from utils.blocked_db import list_mouse_macro_sessions, init_blocked_db
            init_blocked_db()
            real_sessions = list_mouse_macro_sessions()
            if real_sessions:
                return real_sessions
        except Exception:
            pass
        # 실제 데이터 없으면 Mock 폴백
        base_ts = 1744700000000  # 2026-04-15 09:00 UTC (ms)

        def _make_events(seed: int, count: int) -> list[dict]:
            rng = random.Random(seed)
            events = []
            ts  = base_ts + rng.randint(0, 7_200_000)
            x   = rng.randint(200, 1400)
            y   = rng.randint(150, 700)
            for _ in range(count):
                etype    = rng.choices([1, 2, 3, 4, 5], weights=[5, 50, 8, 10, 27])[0]
                interval = rng.randint(8, 12) if etype == 2 else rng.randint(14, 28)
                ts += interval
                if etype == 2:
                    x = max(0, min(1920, x + rng.randint(-4, 4)))
                    y = max(0, min(1080, y + rng.randint(-3, 3)))
                events.append({
                    "timestamp" : ts,
                    "event_type": etype,
                    "screen_x"  : x,
                    "screen_y"  : y,
                })
            return events

        return [
            {
                "session_id" : "MS-7f3a9c12-4e8b-4d1f-9abc-23456789abcd",
                "user_id"    : "user_83021",
                "probability": 0.97,
                "confidence" : 0.93,
                "event_count": 312,
                "detected_at": "2026-04-15T09:23:11+00:00",
                "events"     : _make_events(seed=1, count=312),
            },
            {
                "session_id" : "MS-2b5d8e34-7c1a-4f92-b0de-98765432dcba",
                "user_id"    : "user_44190",
                "probability": 0.91,
                "confidence" : 0.87,
                "event_count": 228,
                "detected_at": "2026-04-15T10:05:42+00:00",
                "events"     : _make_events(seed=2, count=228),
            },
            {
                "session_id" : "MS-c9e12345-6789-4abc-def0-1234567890ef",
                "user_id"    : "",
                "probability": 0.85,
                "confidence" : 0.79,
                "event_count": 180,
                "detected_at": "2026-04-15T10:48:05+00:00",
                "events"     : _make_events(seed=3, count=180),
            },
            {
                "session_id" : "MS-a1b2c3d4-e5f6-4789-0abc-def012345678",
                "user_id"    : "user_61407",
                "probability": 0.78,
                "confidence" : 0.72,
                "event_count": 154,
                "detected_at": "2026-04-15T11:31:29+00:00",
                "events"     : _make_events(seed=4, count=154),
            },
            {
                "session_id" : "MS-f0e9d8c7-b6a5-4432-9876-543210fedcba",
                "user_id"    : "user_29354",
                "probability": 0.94,
                "confidence" : 0.90,
                "event_count": 275,
                "detected_at": "2026-04-15T12:14:57+00:00",
                "events"     : _make_events(seed=5, count=275),
            },
            {
                "session_id" : "MS-e3d2c1b0-a9f8-4321-8765-432109876543",
                "user_id"    : "user_72018",
                "probability": 0.88,
                "confidence" : 0.83,
                "event_count": 196,
                "detected_at": "2026-04-15T12:58:33+00:00",
                "events"     : _make_events(seed=6, count=196),
            },
            {
                "session_id" : "MS-b7a6f5e4-d3c2-4b1a-0987-654321098765",
                "user_id"    : "user_50391",
                "probability": 0.82,
                "confidence" : 0.76,
                "event_count": 143,
                "detected_at": "2026-04-15T13:41:08+00:00",
                "events"     : _make_events(seed=7, count=143),
            },
        ]

    # ── 내부 헬퍼: SQLite에서 기본 데이터 로드 (미사용, 하위 호환용 유지) ──
    @staticmethod
    def _load_history_from_db() -> pd.DataFrame:
        import sqlite3
        try:
            conn = sqlite3.connect("macro_history.db")
            df = pd.read_sql_query("SELECT * FROM history", conn)
            conn.close()
            return df
        except Exception:
            return pd.DataFrame()
