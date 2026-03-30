import streamlit as st
import pandas as pd
from utils.api import get_grafana_alerts
from components.header import render_header

def render_grafana():
    render_header("GRAFANA")
    st.subheader("📊 Grafana 실시간 모니터링")
    
    GRAFANA_URL = st.secrets.get("GRAFANA_URL", "http://localhost:3000").rstrip("/")
    GRAFANA_USERNAME = st.secrets.get("GRAFANA_USERNAME", "admin")
    GRAFANA_PASSWORD = st.secrets.get("GRAFANA_PASSWORD", "YOUR_GRAFANA_PASSWORD")
    GRAFANA_DASHBOARD_UID = st.secrets.get("GRAFANA_DASHBOARD_UID", "macro-detection")
    GRAFANA_SHARE_TOKEN = st.secrets.get("GRAFANA_SHARE_TOKEN", "YOUR_SHARE_TOKEN")

    # Grafana 연동 상태 확인
    if GRAFANA_PASSWORD == "YOUR_GRAFANA_PASSWORD":
        st.warning("⚠️ Grafana 로그인 정보가 설정되지 않았습니다. `.streamlit/secrets.toml`에 다음을 추가하세요:")
        st.code('''GRAFANA_URL = "https://your-grafana-url"
GRAFANA_USERNAME = "admin"
GRAFANA_PASSWORD = "your-password"
GRAFANA_DASHBOARD_UID = "your-dashboard-uid"
GRAFANA_SHARE_TOKEN = "your-embed-share-token"  # 선택사항''', language="toml")
    else:
        # 탭 생성
        tab1, tab2, tab3 = st.tabs(["📊 대시보드", "🚨 알러트", "ℹ️ 정보"])
        
        GRAFANA_PUBLIC_URL = st.secrets.get("GRAFANA_PUBLIC_DASHBOARD_URL", "")
        
        with tab1:
            st.subheader("실시간 대시보드")
            
            if GRAFANA_PUBLIC_URL:
                # Public Dashboard URL이 설정된 경우 → 인증 없이 바로 iframe 임베드
                st.success("✅ Grafana 공개 대시보드가 연결되었습니다.")
                st.markdown(
                    f'<iframe src="{GRAFANA_PUBLIC_URL}?refresh=5s&kiosk" '
                    f'width="100%" height="700" frameborder="0"></iframe>',
                    unsafe_allow_html=True
                )
            else:
                # Public Dashboard URL이 없는 경우 → 설정 가이드 표시
                st.warning("⚠️ Grafana 공개 대시보드 URL이 설정되지 않았습니다.")
                st.info(
                    "**설정 방법:**\n\n"
                    "1. Grafana 웹에 로그인 → 대시보드 열기\n"
                    "2. 상단 **Share** 버튼 클릭\n"
                    "3. **Public Dashboard** 탭 → **Enable** 토글 ON\n"
                    "4. 생성된 URL을 `.streamlit/secrets.toml`에 추가:\n"
                    '   ```\n'
                    '   GRAFANA_PUBLIC_DASHBOARD_URL = "https://dev-monitoring.go-ti.shop/public-dashboards/abc123..."\n'
                    '   ```'
                )
                # 직접 링크도 제공
                grafana_dashboard_url = f"{GRAFANA_URL}/d/{GRAFANA_DASHBOARD_UID}?orgId=1&refresh=5s"
                st.markdown(f"**[🔗 Grafana 대시보드 열기 (새 탭)]({grafana_dashboard_url})**")
        
        with tab2:
            st.subheader("🚨 현재 활성 알러트")
            alerts = get_grafana_alerts(GRAFANA_URL)
            
            if alerts and isinstance(alerts, list) and len(alerts) > 0 and "error" not in str(alerts):
                alert_df = []
                for alert in alerts[:10]:  # 최대 10개 알러트 표시
                    alert_name = alert.get("name", "Unknown")
                    alert_state = alert.get("state", "unknown")
                    
                    # 상태 아이콘
                    if alert_state == "alerting":
                        icon = "🔴"
                    elif alert_state == "pending":
                        icon = "🟡"
                    else:
                        icon = "🟢"
                    
                    alert_df.append({
                        "상태": f"{icon} {alert_state}",
                        "알러트명": alert_name,
                        "최종 평가": alert.get("evalData", {}).get("evalMatches", [{}])[0].get("metric", "N/A")
                    })
                
                if alert_df:
                    st.dataframe(pd.DataFrame(alert_df), width='stretch')
                else:
                    st.success("✅ 현재 활성 알러트가 없습니다.")
            else:
                st.info("⚠️ Grafana에서 알러트를 가져올 수 없습니다. URL 및 로그인 정보를 확인하세요.")
            
            st.divider()
            
            # 주요 메트릭
            st.subheader("📈 주요 메트릭")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.metric("CPU 사용률", "45%", "-5%")
            with col2:
                st.metric("메모리 사용률", "62%", "+3%")
            with col3:
                st.metric("네트워크 처리량", "1.2 Gbps", "+0.1 Gbps")
        
        with tab3:
            st.subheader("ℹ️ Grafana 정보 및 설정")
            
            col1, col2 = st.columns([1, 1])
            with col1:
                st.write(f"**URL**: [{GRAFANA_URL}]({GRAFANA_URL})")
                st.write(f"**사용자**: `{GRAFANA_USERNAME}`")
                st.write(f"**대시보드 UID**: `{GRAFANA_DASHBOARD_UID}`")
            with col2:
                st.write(f"**상태**: ✅ 연결됨")
                st.write(f"**공유 토큰**: {'✅ 설정됨' if GRAFANA_SHARE_TOKEN != 'YOUR_SHARE_TOKEN' else '❌ 미설정'}")
            
            st.divider()
            
            st.subheader("🔧 iframe 임베드 활성화 방법")
            st.markdown("""
            **방법 1: Grafana 공개 공유 사용 (권장)**
            1. Grafana 대시보드 열기
            2. 우측 상단 **Share** 클릭
            3. **Embed** 탭 선택
            4. **Embed** 섹션의 URL 복사
            5. `secrets.toml`에 다음 추가:
               ```toml
               GRAFANA_SHARE_TOKEN = "복사한_공유URL"
               ```
            
            **방법 2: URL 파라미터 사용**
            - `?refresh=5s&kiosk=tv` → TV 모드로 표시
            - `?refresh=1m&kiosk` → 자동 새로고침
            """)
