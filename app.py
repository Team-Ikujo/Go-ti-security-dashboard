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

# 앱 최상단에 배치
hide_streamlit_style = """
                <style>
                div[data-testid="stToolbar"] {
                visibility: hidden;
                height: 0%;
                position: fixed;
                }
                div[data-testid="stDecoration"] {
                visibility: hidden;
                height: 0%;
                position: fixed;
                }
                div[data-testid="stStatusWidget"] {
                visibility: hidden;
                height: 0%;
                position: fixed;
                }
                #MainMenu {
                visibility: hidden;
                height: 0%;
                }
                header {
                visibility: hidden;
                height: 0%;
                }
                footer {
                visibility: hidden;
                height: 0%;
                }
                </style>
                """
st.markdown(hide_streamlit_style, unsafe_allow_html=True)

if not hasattr(st, "experimental_rerun"):
    st.experimental_rerun = st.rerun

# SSL 경고 억제 (개발 환경 자체 서명 인증서 사용 시)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

st.set_page_config(page_title="Go-Ti Security Admin", layout="wide")

# --- DB 연결 및 데이터 로드 예시 ---
def load_history_from_db():
    conn = sqlite3.connect('macro_history.db')  # DB 파일
    df = pd.read_sql_query("SELECT * FROM history", conn)
    conn.close()
    return df

# 데이터가 없으면 샘플 데이터로 초기화
def init_db():
    conn = sqlite3.connect('macro_history.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS history (
                        id INTEGER PRIMARY KEY,
                        접속시간 TEXT,
                        접속IP TEXT,
                        탐지유형 TEXT
                    )''')
    # 샘플 데이터 삽입 (실제로는 API나 다른 소스에서)
    sample_data = [
        ("10:23:32", "203.242.89.166", "동적 행위분석"),
        ("10:23:31", "218.234.23.186", "정적 통계분석"),
        ("10:23:30", "112.111.22.33", "LLM 심층분석")
    ]
    conn.executemany("INSERT OR IGNORE INTO history (접속시간, 접속IP, 탐지유형) VALUES (?, ?, ?)", sample_data)
    conn.commit()
    conn.close()

init_db()  # 앱 시작 시 DB 초기화

# --- Grafana API 연동 함수 ---
def get_grafana_headers():
    """Grafana Basic Auth 헤더 생성"""
    username = st.secrets.get("GRAFANA_USERNAME", "admin")
    password = st.secrets.get("GRAFANA_PASSWORD", "YOUR_GRAFANA_PASSWORD")
    
    # username:password를 Base64로 인코딩
    credentials = f"{username}:{password}"
    encoded_credentials = base64.b64encode(credentials.encode()).decode()
    
    return {
        "Authorization": f"Basic {encoded_credentials}",
        "Content-Type": "application/json"
    }

def get_grafana_metrics(grafana_url, dashboard_uid):
    """Grafana에서 대시보드 정보 및 메트릭 가져오기"""
    try:
        headers = get_grafana_headers()
        
        # 대시보드 정보 가져오기
        response = requests.get(f"{grafana_url}/api/dashboards/uid/{dashboard_uid}", headers=headers, timeout=5, verify=False)
        
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Grafana API 오류: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def get_grafana_alerts(grafana_url):
    """Grafana에서 현재 알러트 상태 가져오기"""
    try:
        headers = get_grafana_headers()
        response = requests.get(f"{grafana_url}/api/alerts", headers=headers, timeout=5, verify=False)
        
        if response.status_code == 200:
            return response.json()
        else:
            return []
    except Exception as e:
        return [{"error": str(e)}]

# --- 1. 인증 로직 (테스트 모드 지원) ---
POOL_ID = st.secrets.get("COGNITO_USER_POOL_ID", "YOUR_POOL_ID")
APP_CLIENT_ID = st.secrets.get("COGNITO_APP_CLIENT_ID", "YOUR_CLIENT_ID")
APP_CLIENT_SECRET = st.secrets.get("COGNITO_APP_CLIENT_SECRET", "YOUR_CLIENT_SECRET")

# Session state 초기화
if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = False
if "authenticator" not in st.session_state:
    st.session_state.authenticator = None
if "username" not in st.session_state:
    st.session_state.username = None

# OIDC 로그인 시 Streamlit 내장 st.user 객체 사용 가능
if hasattr(st, "user"):
    try:
        user_info = st.user.to_dict() if hasattr(st.user, "to_dict") else dict(st.user)
    except Exception:
        user_info = {}

    if user_info:
        st.session_state.is_logged_in = True
        st.session_state.username = user_info.get("given_name") or user_info.get("email") or "Authenticated User"

# 키를 입력하지 않은 초기 실행 상태면 바로 화면을 볼 수 있게 테스트 모드로 통과시킵니다.
if POOL_ID == "YOUR_POOL_ID":
    st.session_state.is_logged_in = True
    st.sidebar.warning("⚠️ 테스트 모드 (Cognito 연동 전)")
else:
    # st.user가 없거나 OIDC 비활성 시 CognitoAuthenticator 사용
    if not st.session_state.is_logged_in:
        if st.session_state.authenticator is None:
            st.session_state.authenticator = CognitoAuthenticator(
                pool_id=POOL_ID,
                app_client_id=APP_CLIENT_ID,
                app_client_secret=APP_CLIENT_SECRET,
            )

        # 이미 로그인되어 있지 않으면 로그인 시도
        st.session_state.is_logged_in = st.session_state.authenticator.login()

        # 로그인 성공 후 username 저장
        if st.session_state.is_logged_in:
            try:
                ua = st.session_state
                username = ua.get("username") if ua else None
                if not username:
                    username = ua.get("auth_email") if ua else None
            except (AttributeError, TypeError):
                username = None

            st.session_state.username = username or "Authenticated User"

if not st.session_state.is_logged_in:
    st.info("Go-Ti 보안팀 Admin 시스템입니다. 등록된 관리자 계정으로 로그인해주세요.")
    st.stop()

def logout():
    """로그아웃 함수"""
    if POOL_ID != "YOUR_POOL_ID":
        st.session_state.authenticator.logout()
    st.session_state.is_logged_in = False
    st.session_state.authenticator = None
    st.session_state.username = None

# --- 2. Upstage API 클라이언트 ---
UPSTAGE_API_KEY = st.secrets.get("UPSTAGE_API_KEY", "YOUR_UPSTAGE_API_KEY")
solar_client = OpenAI(api_key=UPSTAGE_API_KEY, base_url="https://api.upstage.ai/v1/solar")

# --- 2-1. Grafana 설정 ---
GRAFANA_URL = st.secrets.get("GRAFANA_URL", "http://localhost:3000").rstrip("/")  # 끝의 / 제거
GRAFANA_USERNAME = st.secrets.get("GRAFANA_USERNAME", "admin")
GRAFANA_PASSWORD = st.secrets.get("GRAFANA_PASSWORD", "YOUR_GRAFANA_PASSWORD")
GRAFANA_API_KEY = st.secrets.get("GRAFANA_API_KEY", "YOUR_GRAFANA_API_KEY")
GRAFANA_SHARE_TOKEN = st.secrets.get("GRAFANA_SHARE_TOKEN", "YOUR_SHARE_TOKEN")
GRAFANA_DASHBOARD_UID = st.secrets.get("GRAFANA_DASHBOARD_UID", "macro-detection")  # 대시보드 UID

# --- 3. 사이드바 ---
with st.sidebar:
    st.title("🦠 Go-Ti Security Admin")
    
    # 로그인한 사용자 정보 표시
    if st.session_state.username:
        st.caption(f"**👤 {st.session_state.username}**")
        st.divider()
    
    menu = st.radio("MENU", ["실시간 매크로 모니터링", "AI 방어 어시스턴트", "의심 유저 수동 심사", "Grafana"])
    st.divider()
    st.button("로그아웃", on_click=logout)

# --- 4. 화면 라우팅 ---
if menu == "실시간 매크로 모니터링":
    st.subheader("📊 실시간 매크로 접속 현황")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("금일 접속 건수", "14,859 건", "+120")
    col2.metric("접속자 건수", "6,513 건", "-40")
    col3.metric("매크로 차단 건수", "8,346 건", "+500")
    col4.metric("차단율", "56.2%", "1.2%")
    
    st.divider()
    left_col, right_col = st.columns([1, 1])
    
    with left_col:
        st.markdown("**탐지 유형별 차단 현황**")
        df_chart = pd.DataFrame({"유형": ["행위분석", "해외접속", "접속통계"], "건수": [4752, 2830, 479]})
        fig = px.bar(df_chart, x="유형", y="건수", color="유형", text_auto=True)
        st.plotly_chart(fig, width='stretch')

    with right_col:
        st.markdown("**최근 매크로 차단 이력**")
        df_history = load_history_from_db()
        st.dataframe(df_history, width='stretch', hide_index=True)

elif menu == "AI 방어 어시스턴트":
    st.subheader("🫆 매크로 방어 정책 에이전트")
    
    # 최근 매크로 차단 이력 데이터 준비 (DB에서 로드)
    df_history = load_history_from_db()
    history_text = df_history.to_string(index=False)
    
    system_prompt = f"Go-Ti 매크로 관제 에이전트입니다. 다음은 최근 매크로 차단 이력 데이터입니다:\n{history_text}\n\n이 데이터를 참고하여 사용자의 질문에 답변하세요."
    
    if "messages" not in st.session_state:
        st.session_state.messages = [{"role": "system", "content": system_prompt}, {"role": "assistant", "content": "무엇을 도와드릴까요?"}]

    for msg in st.session_state.messages:
        if msg["role"] != "system":  # 시스템 메시지는 표시하지 않음
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])

    if prompt := st.chat_input("메시지를 입력하세요."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
            
        with st.chat_message("assistant"):
            if UPSTAGE_API_KEY == "YOUR_UPSTAGE_API_KEY":
                response = "API 키가 등록되지 않았습니다. `.streamlit/secrets.toml`을 확인해주세요."
                st.markdown(response)
                st.session_state.messages.append({"role": "assistant", "content": response})
            else:
                message_placeholder = st.empty()
                full_response = ""
                api_response = solar_client.chat.completions.create(
                    model="solar-pro",
                    messages=st.session_state.messages,
                    stream=True
                )
                for chunk in api_response:
                    if chunk.choices[0].delta.content is not None:
                        full_response += chunk.choices[0].delta.content
                        message_placeholder.markdown(full_response + "▌")
                message_placeholder.markdown(full_response)
                st.session_state.messages.append({"role": "assistant", "content": full_response})

elif menu == "의심 유저 수동 심사":
    st.subheader("⚖️ 고위험 의심 계정 수동 검토")
    if "suspicious_users" not in st.session_state:
        st.session_state.suspicious_users = [
            {"id": "sess_8f2a1", "ip": "112.111.22.33", "score": 0.89, "status": "대기중", "reason": "직선성 임계치 근접"}
        ]

    pending_users = [u for u in st.session_state.suspicious_users if u["status"] == "대기중"]
    if not pending_users:
        st.success("대기 중인 유저가 없습니다.")
    else:
        for idx, user in enumerate(pending_users):
            with st.container():
                st.markdown(f"**ID:** `{user['id']}` | **IP:** {user['ip']} | **위험도:** {user['score']}")
                col1, col2 = st.columns([1, 1])
                with col1:
                    if st.button("🚫 차단 및 환불", key=f"block_{user['id']}"):
                        user["status"] = "차단"
                        st.session_state.suspicious_users[idx] = user
                        st.rerun()
                with col2:
                    if st.button("✅ 통과", key=f"pass_{user['id']}"):
                        user["status"] = "통과"
                        st.session_state.suspicious_users[idx] = user
                        st.rerun()
                st.divider()
elif menu == "Grafana":
    st.subheader("📊 Grafana 실시간 모니터링")
    
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
        
        with tab1:
            st.subheader("실시간 대시보드")
            
            # 공개 공유 토큰이 있으면 iframe으로 임베드, 없으면 링크 제공
            if GRAFANA_SHARE_TOKEN != "YOUR_SHARE_TOKEN":
                st.info("✅ 공개 공유 대시보드로 iframe 표시 중입니다.")
                # 공개 공유 토큰을 사용한 임베드 URL
                embed_url = f"{GRAFANA_URL}/render/d-solo/{GRAFANA_DASHBOARD_UID}?refresh=5s&kiosk=tv"
                st.markdown(f'<iframe src="{embed_url}" width="100%" height="700" frameborder="0"></iframe>', unsafe_allow_html=True)
            else:
                st.info("💡 **iframe 임베드를 활성화하려면:**\n\n1. Grafana → 해당 대시보드 → Share\n2. **Embed** 탭에서 Embed 옵션 복사\n3. URL의 `kiosk` 파라미터 추가: `?refresh=5s&kiosk=tv`\n4. 공유 토큰을 `secrets.toml`의 `GRAFANA_SHARE_TOKEN`에 저장")
                
                # 또는 직접 링크 제공
                grafana_dashboard_url = f"{GRAFANA_URL}d/{GRAFANA_DASHBOARD_UID}?orgId=1&refresh=5s"
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

