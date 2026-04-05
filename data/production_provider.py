"""
ProductionDataProvider — OpenSearch 조회 + 백엔드 API 연동 구현체.

백엔드 팀 개발 완료 시 바로 연동할 수 있도록 실제 HTTP 호출 로직이 구현되어 있습니다.
연결 실패 시에는 graceful error 메시지를 표시합니다.

TODO: 백엔드 팀 API 스펙 확정 후 아래 엔드포인트 / 필드명 조정
"""
import requests
import pandas as pd
import streamlit as st

from data.provider import DataProvider
from utils.config import get_api_base_url, get_opensearch_config


class ProductionDataProvider(DataProvider):
    """실제 백엔드 API 및 OpenSearch와 통신하는 Production DataProvider."""

    def __init__(self):
        self.api_base = get_api_base_url()
        self.os_config = get_opensearch_config()
        # TODO: API 인증 토큰이 필요한 경우 여기에 헤더 설정
        self.headers = {
            "Content-Type": "application/json",
            # "Authorization": f"Bearer {st.secrets.get('API_AUTH_TOKEN', '')}",
        }

    # ─────────────────────────────────────────────
    # 내부 헬퍼: 안전한 API 호출
    # ─────────────────────────────────────────────
    def _safe_get(self, endpoint: str, params: dict = None, timeout: int = 10) -> dict | list | None:
        """GET 요청을 안전하게 수행하고, 실패 시 None을 반환합니다."""
        url = f"{self.api_base}{endpoint}"
        try:
            resp = requests.get(url, headers=self.headers, params=params, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.ConnectionError:
            st.error(f"🔴 **API 연결 실패** — `{url}`에 연결할 수 없습니다. 백엔드 서버 상태를 확인하세요.")
        except requests.exceptions.Timeout:
            st.error(f"⏳ **API 타임아웃** — `{url}` 응답이 {timeout}초를 초과했습니다.")
        except requests.exceptions.HTTPError as e:
            st.error(f"❌ **API 오류** — {e.response.status_code}: {e.response.text[:200]}")
        except Exception as e:
            st.error(f"⚠️ **예기치 않은 오류** — {str(e)}")
        return None

    def _safe_post(self, endpoint: str, payload: dict, timeout: int = 10) -> dict | None:
        """POST 요청을 안전하게 수행하고, 실패 시 None을 반환합니다."""
        url = f"{self.api_base}{endpoint}"
        try:
            resp = requests.post(url, headers=self.headers, json=payload, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.ConnectionError:
            st.error(f"🔴 **API 연결 실패** — `{url}`에 연결할 수 없습니다.")
        except requests.exceptions.Timeout:
            st.error(f"⏳ **API 타임아웃** — `{url}` 응답이 {timeout}초를 초과했습니다.")
        except requests.exceptions.HTTPError as e:
            st.error(f"❌ **API 오류** — {e.response.status_code}: {e.response.text[:200]}")
        except Exception as e:
            st.error(f"⚠️ **예기치 않은 오류** — {str(e)}")
        return None

    # ─────────────────────────────────────────────
    # DataProvider 구현
    # ─────────────────────────────────────────────

    def get_dashboard_stats(self) -> dict:
        """
        TODO: 백엔드 API 응답 형식에 맞게 필드 매핑 조정
        Expected API: GET /api/v1/stats/summary
        Expected Response:
        {
            "total_access": 14859,
            "total_access_delta": "+120",
            "unique_users": 6513,
            "unique_users_delta": "-40",
            "blocked_count": 8346,
            "blocked_delta": "+500",
            "block_rate": 56.2,
            "block_rate_delta": "+1.2%"
        }
        """
        data = self._safe_get("/api/v1/stats/summary")

        if data is None:
            # API 연결 실패 시 빈 기본값 반환
            return {
                "total_access": 0, "total_access_delta": "-", "total_access_badge": "badge-up",
                "unique_users": 0, "unique_users_delta": "-", "unique_users_badge": "badge-up",
                "blocked_count": 0, "blocked_delta": "-", "blocked_badge": "badge-up",
                "block_rate": 0.0, "block_rate_delta": "-", "block_rate_badge": "badge-up",
            }

        # TODO: 백엔드 응답 필드명이 다를 경우 여기에서 매핑
        def _delta_badge(delta_str: str) -> str:
            """변동값에 따라 CSS 배지 클래스 결정."""
            if not delta_str or delta_str == "-":
                return "badge-up"
            return "badge-down" if delta_str.startswith("-") or "↓" in delta_str else "badge-up"

        def _delta_display(delta_str: str) -> str:
            """변동값에 화살표 추가."""
            if not delta_str or delta_str == "-":
                return "-"
            if delta_str.startswith("-"):
                return f"↓ {delta_str}"
            return f"↑ +{delta_str}" if not delta_str.startswith("+") else f"↑ {delta_str}"

        ta_delta = str(data.get("total_access_delta", "-"))
        uu_delta = str(data.get("unique_users_delta", "-"))
        bc_delta = str(data.get("blocked_delta", "-"))
        br_delta = str(data.get("block_rate_delta", "-"))

        return {
            "total_access": data.get("total_access", 0),
            "total_access_delta": _delta_display(ta_delta),
            "total_access_badge": _delta_badge(ta_delta),
            "unique_users": data.get("unique_users", 0),
            "unique_users_delta": _delta_display(uu_delta),
            "unique_users_badge": _delta_badge(uu_delta),
            "blocked_count": data.get("blocked_count", 0),
            "blocked_delta": _delta_display(bc_delta),
            "blocked_badge": _delta_badge(bc_delta),
            "block_rate": data.get("block_rate", 0.0),
            "block_rate_delta": _delta_display(br_delta),
            "block_rate_badge": _delta_badge(br_delta),
        }

    def get_enriched_history(self) -> pd.DataFrame:
        """
        TODO: 백엔드 API 응답의 컬럼명을 대시보드 구조에 맞게 매핑
        Expected API: GET /api/v1/detections
        Expected Response: JSON Array
        [
            {
                "event_id": "#VZ1000",
                "access_date": "2026-03-31",
                "access_time": "10:23:32",
                "game_title": "2026 KBO ...",
                "ip_address": "203.242.89.166",
                "target_url": "/login",
                "detection_type": "동적 행위분석",
                "status": "Blocked",
                "risk_score": 94
            }, ...
        ]
        """
        data = self._safe_get("/api/v1/detections")

        if data is None:
            st.warning("⚠️ 탐지 이벤트 데이터를 불러올 수 없습니다. API 연결을 확인하세요.")
            return pd.DataFrame()

        try:
            df = pd.DataFrame(data)

            # TODO: 백엔드 응답 필드명 → 대시보드 컬럼명 매핑
            column_mapping = {
                "event_id": "Event ID",
                "access_date": "접속일자",
                "access_time": "접속시간",
                "game_title": "대상 경기",
                "ip_address": "접속IP",
                "target_url": "Target URL",
                "detection_type": "탐지유형",
                "status": "Status",
                "risk_score": "Risk Score",
            }
            df = df.rename(columns=column_mapping)

            expected_cols = ["Event ID", "접속일자", "접속시간", "대상 경기", "접속IP", "Target URL", "탐지유형", "Status", "Risk Score"]
            for col in expected_cols:
                if col not in df.columns:
                    df[col] = "N/A"

            return df[expected_cols]

        except Exception as e:
            st.error(f"⚠️ 탐지 데이터 파싱 오류: {str(e)}")
            return pd.DataFrame()

    def get_detection_report(self, event_id: str) -> dict:
        """
        TODO: OpenSearch 인덱스 / 필드명을 백엔드 API 스펙에 맞게 조정
        Expected API: GET /api/v1/reports/{event_id}
        Expected Response:
        {
            "index": "macro-events-2026.03",
            "_id": "doc_xxx",
            "threat_score": 94,
            "matched_rules": ["Rule A", "Rule B"],
            "raw_logs": { ... }
        }
        """
        # event_id에서 '#' 제거하여 URL-safe하게 변환
        safe_id = event_id.replace("#", "")
        data = self._safe_get(f"/api/v1/reports/{safe_id}")

        if data is None:
            return {
                "index": "connection-error",
                "_id": "N/A",
                "threat_score": "N/A",
                "matched_rules": ["API 연결 실패 — 백엔드 서버를 확인하세요."],
                "raw_logs": {"error": "Could not retrieve report from production API."}
            }

        return data

    def update_event_status(self, event_id: str, new_status: str) -> bool:
        """
        TODO: 백엔드 API 요청/응답 스펙 확정 후 조정
        Expected API: POST /api/v1/interventions/{event_id}/action
        Expected Payload: { "action": "Blocked" | "Passed" }
        Expected Response: { "success": true, "message": "..." }
        """
        safe_id = event_id.replace("#", "")
        payload = {"action": new_status}

        print(f"[PRODUCTION] POST /api/v1/interventions/{safe_id}/action -> {payload}")

        result = self._safe_post(f"/api/v1/interventions/{safe_id}/action", payload)

        if result is None:
            st.error(f"🔴 {event_id} 상태 업데이트 실패 — API 연결을 확인하세요.")
            return False

        success = result.get("success", False)
        if success:
            print(f"[PRODUCTION] Event {event_id} status updated to {new_status}.")
        else:
            st.warning(f"⚠️ {event_id} 상태 업데이트 실패: {result.get('message', 'Unknown error')}")

        return success

    def get_geo_detection_data(self) -> pd.DataFrame:
        """
        TODO: 백엔드 API 스펙 확정 후 조정
        Expected API: GET /api/v1/stats/geo
        Expected Response:
        [
            {"country": "Korea", "lat": 37.5665, "lon": 126.978, "detections": 700},
            ...
        ]
        """
        data = self._safe_get("/api/v1/stats/geo")

        if data is None:
            return pd.DataFrame(columns=["Country", "Lat", "Lon", "Detections"])

        try:
            df = pd.DataFrame(data)
            column_mapping = {"country": "Country", "lat": "Lat", "lon": "Lon", "detections": "Detections"}
            df = df.rename(columns=column_mapping)
            return df
        except Exception as e:
            st.error(f"⚠️ 지도 데이터 파싱 오류: {str(e)}")
            return pd.DataFrame(columns=["Country", "Lat", "Lon", "Detections"])

    def get_guardrail_events(self) -> list[dict]:
        try:
            from utils.blocked_db import list_blocked_events, init_blocked_db
            init_blocked_db()
            return list_blocked_events()
        except Exception:
            return []

    def get_mouse_macro_sessions(self) -> list[dict]:
        """마우스 서버에서 수신된 실제 세션 데이터를 반환합니다."""
        try:
            from utils.blocked_db import list_mouse_macro_sessions, init_blocked_db
            init_blocked_db()
            return list_mouse_macro_sessions()
        except Exception:
            return []

    def get_detection_type_stats(self) -> pd.DataFrame:
        """
        TODO: 백엔드 API 스펙 확정 후 조정
        Expected API: GET /api/v1/stats/detection-types
        Expected Response:
        [
            {"type": "Mouse Macro", "count": 240},
            {"type": "API Abuse", "count": 180},
            ...
        ]
        """
        data = self._safe_get("/api/v1/stats/detection-types")

        if data is None:
            return pd.DataFrame(columns=["Type", "Count"])

        try:
            df = pd.DataFrame(data)
            column_mapping = {"type": "Type", "count": "Count"}
            df = df.rename(columns=column_mapping)
            return df
        except Exception as e:
            st.error(f"⚠️ 탐지 유형 데이터 파싱 오류: {str(e)}")
            return pd.DataFrame(columns=["Type", "Count"])
