"""
DataProvider ABC 인터페이스 및 팩토리 함수.
APP_MODE에 따라 MockDataProvider 또는 ProductionDataProvider를 반환합니다.
"""
from abc import ABC, abstractmethod
import pandas as pd
import streamlit as st


class DataProvider(ABC):
    """대시보드 데이터 소스의 공통 인터페이스."""

    # ── 대시보드 상단 지표 카드 ──
    @abstractmethod
    def get_dashboard_stats(self) -> dict:
        """
        Returns:
            {
                "total_access": int,       # 금일 접속 건수
                "total_access_delta": str,  # 변동 (예: "+120")
                "unique_users": int,        # 접속자 건수
                "unique_users_delta": str,
                "blocked_count": int,       # 매크로 차단 건수
                "blocked_delta": str,
                "block_rate": float,        # 차단율 (%)
                "block_rate_delta": str,
            }
        """
        pass

    # ── 탐지 이벤트 리스트 (메인 테이블 + 리뷰 페이지) ──
    @abstractmethod
    def get_enriched_history(self) -> pd.DataFrame:
        """
        Returns:
            DataFrame with columns:
            [Event ID, 접속일자, 접속시간, 대상 경기, 접속IP,
             Target URL, 탐지유형, Status, Risk Score]
        """
        pass

    # ── OpenSearch 상세 분석 리포트 ──
    @abstractmethod
    def get_detection_report(self, event_id: str) -> dict:
        """
        Returns:
            {
                "index": str,
                "_id": str,
                "threat_score": int,
                "matched_rules": list[str],
                "raw_logs": dict,
            }
        """
        pass

    # ── 수동 차단/통과 처리 ──
    @abstractmethod
    def update_event_status(self, event_id: str, new_status: str) -> bool:
        """
        Args:
            event_id: 이벤트 식별자 (예: "#VZ1000")
            new_status: "Blocked" 또는 "Passed"
        Returns:
            성공 여부
        """
        pass

    # ── 국가별 매크로 탐지 지도 데이터 ──
    @abstractmethod
    def get_geo_detection_data(self) -> pd.DataFrame:
        """
        Returns:
            DataFrame with columns: [Country, Lat, Lon, Detections]
        """
        pass

    # ── 탐지 유형별 통계 (바 차트) ──
    @abstractmethod
    def get_detection_type_stats(self) -> pd.DataFrame:
        """
        Returns:
            DataFrame with columns: [Type, Count]
        """
        pass

    # ── 가드레일 차단 이벤트 목록 ──
    @abstractmethod
    def get_guardrail_events(self) -> list[dict]:
        """
        Returns:
            list of {event_id, session_id, user_id, ip_address, risk_score,
                     reason_codes, webdriver, headless, devtools_protocol,
                     plugins_count, languages_count, blocked_at, status}
        """
        pass

    # ── 마우스 매크로 세션 목록 ──
    @abstractmethod
    def get_mouse_macro_sessions(self) -> list[dict]:
        """
        Returns:
            list of {session_id, probability, confidence, event_count, events, detected_at}
        """
        pass


# ─────────────────────────────────────────────
# 팩토리 함수
# ─────────────────────────────────────────────
_provider_instance: DataProvider | None = None


def get_provider() -> DataProvider:
    """
    APP_MODE 설정에 따라 적절한 DataProvider 인스턴스를 싱글톤으로 반환합니다.
    Streamlit의 session_state를 싱글톤 스토리지로 활용합니다.
    """
    if "data_provider" not in st.session_state:
        from utils.config import get_app_mode, MODE_MOCK

        mode = get_app_mode()
        if mode == MODE_MOCK:
            from data.mock_provider import MockDataProvider
            st.session_state.data_provider = MockDataProvider()
        else:
            from data.production_provider import ProductionDataProvider
            st.session_state.data_provider = ProductionDataProvider()

    return st.session_state.data_provider
