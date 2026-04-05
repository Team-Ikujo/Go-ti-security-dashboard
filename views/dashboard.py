import numpy as np
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import folium
from components.header import render_header
from components.agent_history import render_agent_history
from data.provider import get_provider

def render_dashboard():
    provider = get_provider()
    
    # Top Header Injection
    render_header()
    st.markdown('<div class="section-title" style="margin-top: 25px;">매크로 탐지 현황</div>', unsafe_allow_html=True)
    
    # 1. Top Metrics Cards — Provider에서 데이터 가져오기
    stats = provider.get_dashboard_stats()
    
    cards_html = f"""
    <div class="metric-card-container">
        <div class="m-stat-card">
            <div class="m-stat-title">금일 접속 건수</div>
            <div><span class="m-stat-value">{stats['total_access']:,}</span><span class="m-stat-unit">건</span></div>
            <div class="m-stat-badge {stats['total_access_badge']}">{stats['total_access_delta']}</div>
        </div>
        <div class="m-stat-card">
            <div class="m-stat-title">접속자 건수</div>
            <div><span class="m-stat-value">{stats['unique_users']:,}</span><span class="m-stat-unit">건</span></div>
            <div class="m-stat-badge {stats['unique_users_badge']}">{stats['unique_users_delta']}</div>
        </div>
        <div class="m-stat-card">
            <div class="m-stat-title">매크로 차단 건수</div>
            <div><span class="m-stat-value">{stats['blocked_count']:,}</span><span class="m-stat-unit">건</span></div>
            <div class="m-stat-badge {stats['blocked_badge']}">{stats['blocked_delta']}</div>
        </div>
        <div class="m-stat-card">
            <div class="m-stat-title">차단율</div>
            <div><span class="m-stat-value">{stats['block_rate']}</span><span class="m-stat-unit">%</span></div>
            <div class="m-stat-badge {stats['block_rate_badge']}">{stats['block_rate_delta']}</div>
        </div>
    </div>
    """
    st.markdown(cards_html, unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # 2. Middle Row: Map & Agent History
    col_charts, col_map = st.columns([1, 1.5], gap="large")
    
    with col_map:
        st.markdown('<div class="section-title" style="margin-top: 10%;">매크로 발생 주요 국가</div>', unsafe_allow_html=True)
        
        # Provider에서 지도 데이터 가져오기
        loc_data = provider.get_geo_detection_data()
        
        if not loc_data.empty:
            my_map = folium.Map(
                location=[loc_data['Lat'].mean(), loc_data['Lon'].mean()], 
                zoom_start=2,
                tiles='CartoDB Positron'
            )
            
            for index, row in loc_data.iterrows():
                folium.CircleMarker(
                    location=[row['Lat'], row['Lon']],
                    radius=row['Detections'] / 30,
                    color='#ef4444',             
                    fill=True,
                    fill_color='#ef4444',
                    fill_opacity=0.5,
                    weight=1
                ).add_to(my_map)

                folium.Marker(
                    location=[row['Lat'], row['Lon']],
                    icon=folium.DivIcon(
                        html=f"<div style='font-size: 11px; font-weight: 700; color: #1e293b; background: rgba(255,255,255,0.6); padding: 2px 4px; border-radius: 4px; border: 1px solid #cbd5e1; white-space: nowrap; transform: translate(-50%, -150%);'>{row['Country']} {row['Detections']}</div>"
                    ),
                ).add_to(my_map)
                
            st.components.v1.html(my_map._repr_html_(), height=480)
        else:
            st.info("지도 데이터를 불러올 수 없습니다.")

    with col_charts:
        st.markdown('<div class="chart-bg-target"></div>', unsafe_allow_html=True)
        st.markdown('<div class="section-title">매크로 조치 현황</div>', unsafe_allow_html=True)
        from components.charts import render_status_donut_chart
        df_history = provider.get_enriched_history()
        render_status_donut_chart(df_history, height=220)
        
        st.markdown('<div class="section-title" style="margin-top: 25px;">탐지 유형 통계</div>', unsafe_allow_html=True)
        
        # Provider에서 바 차트 데이터 가져오기
        bar_data = provider.get_detection_type_stats()
        
        if not bar_data.empty:
            fig_bar = px.bar(
                bar_data, x="Count", y="Type", orientation='h',
                color="Type",
                color_discrete_sequence=["#8b5cf6", "#14b8a6", "#ec4899", "#f59e0b"]
            )
            fig_bar.update_layout(
                margin=dict(l=0, r=10, t=10, b=0), 
                height=200, 
                showlegend=False,
                xaxis=dict(title="", showgrid=False),
                yaxis=dict(title="")
            )
            st.plotly_chart(fig_bar, width="stretch")
        else:
            st.info("탐지 유형 데이터를 불러올 수 없습니다.")

    st.markdown("<br>", unsafe_allow_html=True)
    
    # 3. Middle Row: Agent History
    render_agent_history()
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # 4. Recent Detections List (가드레일 + 마우스 매크로 통합)
    st.markdown('<div class="section-title">Recent Detections List</div>', unsafe_allow_html=True)
    _render_recent_detections(provider)

    st.markdown("<br>", unsafe_allow_html=True)

    # 6. Mouse Macro Detections
    col_title, col_refresh = st.columns([6, 1])
    with col_title:
        st.markdown('<div class="section-title">Mouse Macro Detections</div>', unsafe_allow_html=True)
    with col_refresh:
        if st.button("새로고침", key="refresh_mouse_macro"):
            st.rerun()
    _render_mouse_macro_section(provider)


# ─────────────────────────────────────────────
# Recent Detections List (통합)
# ─────────────────────────────────────────────

def _render_recent_detections(provider):
    """가드레일 + 마우스 매크로 이벤트를 통합해 단일 테이블로 표시합니다."""
    rows = []

    # 가드레일 이벤트
    for e in provider.get_guardrail_events():
        rows.append({
            "출처"      : "가드레일",
            "상태"      : f"{_STATUS_BADGE.get(e.get('status','Blocked'), '')} {e.get('status','Blocked')}",
            "Event ID"  : e.get("event_id", ""),
            "탐지 시각" : (e.get("blocked_at", "")[:19] or "").replace("T", " "),
            "User ID"   : e.get("user_id") or "-",
            "IP 주소"   : e.get("ip_address", ""),
            "탐지 사유" : ", ".join(e.get("reason_codes", [])),
            "Risk Score": int(e.get("risk_score", 0) * 100),
        })

    # 마우스 매크로 이벤트
    for s in provider.get_mouse_macro_sessions():
        rows.append({
            "출처"      : "마우스 매크로",
            "상태"      : "🔴 Blocked",
            "Event ID"  : s.get("session_id", "")[:16] + "...",
            "탐지 시각" : (s.get("detected_at", "")[:19] or "").replace("T", " "),
            "User ID"   : s.get("user_id") or "-",
            "IP 주소"   : "-",
            "탐지 사유" : f"Mouse Macro (확률 {s.get('probability',0)*100:.1f}%)",
            "Risk Score": int(s.get("probability", 0) * 100),
        })

    if not rows:
        st.info("탐지된 이벤트가 없습니다.")
        return

    rows.sort(key=lambda r: r["탐지 시각"], reverse=True)
    df = pd.DataFrame(rows)
    st.dataframe(
        df,
        width="stretch",
        hide_index=True,
        column_config={
            "Risk Score": st.column_config.ProgressColumn(
                "Risk Score", format="%d", min_value=0, max_value=100
            ),
        }
    )


# 가드레일 섹션 렌더러
# ─────────────────────────────────────────────

_STATUS_BADGE = {
    "Blocked": "🔴",
    "Pending": "🟡",
    "Passed" : "🟢",
}

def _render_guardrail_section(provider):
    events = provider.get_guardrail_events()

    if not events:
        st.info("수신된 가드레일 차단 이벤트가 없습니다.")
        return

    rows = []
    for e in events:
        flags = []
        if e.get("webdriver"):         flags.append("Webdriver")
        if e.get("headless"):          flags.append("Headless")
        if e.get("devtools_protocol"): flags.append("DevTools")

        blocked_at = e.get("blocked_at", "")[:19].replace("T", " ")
        status = e.get("status", "Blocked")

        rows.append({
            "상태"      : f"{_STATUS_BADGE.get(status, '')} {status}",
            "Event ID"  : e.get("event_id", ""),
            "차단 시각" : blocked_at,
            "Session ID": e.get("session_id", "")[:16] + "...",
            "User ID"   : e.get("user_id") or "-",
            "IP 주소"   : e.get("ip_address", ""),
            "Risk Score": int(e.get("risk_score", 0) * 100),
            "탐지 사유" : ", ".join(e.get("reason_codes", [])),
            "브라우저 플래그": ", ".join(flags) if flags else "-",
            "Plugins"   : e.get("plugins_count", 0),
            "Languages" : e.get("languages_count", 0),
        })

    df = pd.DataFrame(rows)
    st.dataframe(
        df,
        width="stretch",
        hide_index=True,
        column_config={
            "Risk Score": st.column_config.ProgressColumn(
                "Risk Score", format="%d", min_value=0, max_value=100
            ),
        }
    )


# ─────────────────────────────────────────────
# 마우스 매크로 섹션 렌더러
# ─────────────────────────────────────────────

_EVENT_TYPE_LABEL = {1: "Release", 2: "Move", 3: "Wheel", 4: "Drag", 5: "Click"}
_EVENT_TYPE_COLOR = {1: "#94a3b8", 2: "#3b82f6", 3: "#a855f7", 4: "#f59e0b", 5: "#ef4444"}


def _render_mouse_macro_section(provider):
    sessions = provider.get_mouse_macro_sessions()

    if not sessions:
        st.info("수신된 마우스 매크로 세션이 없습니다.")
        return

    # ── 테이블 ────────────────────────────────
    table_rows = []
    for s in sessions:
        dt = s["detected_at"][:19] if len(s["detected_at"]) >= 19 else s["detected_at"]
        table_rows.append({
            "Session ID"  : s["session_id"][:16] + ("..." if len(s["session_id"]) > 16 else ""),
            "User ID"     : s.get("user_id") or "-",
            "탐지 시간"   : dt,
            "이벤트 수"   : s["event_count"],
            "매크로 확률" : f"{s['probability'] * 100:.1f}%",
            "신뢰도"      : f"{s['confidence'] * 100:.1f}%",
        })

    df_macro = pd.DataFrame(table_rows)
    st.dataframe(df_macro, width="stretch", hide_index=True)

    # ── 경로 시각화 ───────────────────────────
    st.markdown("##### 마우스 이동 경로 시각화")

    session_labels = [s["session_id"][:20] for s in sessions]
    selected_label = st.selectbox("세션 선택", session_labels, key="mouse_macro_session_select")
    selected = next((s for s in sessions if s["session_id"].startswith(selected_label.rstrip("."))), sessions[0])

    events = selected.get("events", [])
    if not events:
        st.info("이벤트 데이터가 없습니다.")
        return

    df_ev = pd.DataFrame(events)
    df_ev["event_label"] = df_ev["event_type"].map(lambda t: _EVENT_TYPE_LABEL.get(t, str(t)))
    df_ev["color"]       = df_ev["event_type"].map(lambda t: _EVENT_TYPE_COLOR.get(t, "#64748b"))

    col_viz, col_stats = st.columns([2, 1], gap="large")

    with col_viz:
        fig = go.Figure()

        # 이동 경로 선
        move_df = df_ev[df_ev["event_type"] == 2]
        if not move_df.empty:
            fig.add_trace(go.Scatter(
                x=move_df["screen_x"], y=move_df["screen_y"],
                mode="lines",
                line=dict(color="#3b82f6", width=1.5),
                name="경로",
                hoverinfo="skip",
            ))

        # 이벤트 타입별 포인트
        for etype, label in _EVENT_TYPE_LABEL.items():
            sub = df_ev[df_ev["event_type"] == etype]
            if sub.empty:
                continue
            color = _EVENT_TYPE_COLOR[etype]
            size  = 10 if etype == 5 else 5
            fig.add_trace(go.Scatter(
                x=sub["screen_x"], y=sub["screen_y"],
                mode="markers",
                marker=dict(color=color, size=size, opacity=0.85),
                name=label,
                customdata=sub[["timestamp"]].values,
                hovertemplate=f"<b>{label}</b><br>x=%{{x:.0f}}, y=%{{y:.0f}}<br>t=%{{customdata[0]}}<extra></extra>",
            ))

        fig.update_layout(
            height=380,
            margin=dict(l=0, r=0, t=10, b=0),
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15,23,42,0.6)",
            xaxis=dict(title="screen_x", showgrid=True, gridcolor="#1e293b", zeroline=False),
            yaxis=dict(title="screen_y", showgrid=True, gridcolor="#1e293b", zeroline=False, autorange="reversed"),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0),
            font=dict(color="#94a3b8"),
        )
        st.plotly_chart(fig, use_container_width=True)

    with col_stats:
        prob_pct = selected["probability"] * 100
        st.markdown(f"**Session:** `{selected['session_id'][:20]}`")
        st.markdown(f"**User ID:** `{selected.get('user_id') or '-'}`")
        st.markdown(f"**매크로 확률:** {prob_pct:.1f}%")
        st.progress(int(prob_pct))
        st.markdown(f"**신뢰도:** {selected['confidence'] * 100:.1f}%")
        st.markdown(f"**총 이벤트:** {selected['event_count']}개")
        st.markdown(f"**탐지 시간:** {selected['detected_at'][:19]}")

        st.markdown("---")
        st.markdown("**이벤트 유형 분포**")
        type_counts = df_ev["event_label"].value_counts().reset_index()
        type_counts.columns = ["유형", "건수"]
        st.dataframe(type_counts, hide_index=True, width="stretch")

        st.markdown("---")
        if st.button("LLM 매크로 원인 분석", key=f"llm_analyze_{selected['session_id']}"):
            with st.spinner("분석 중..."):
                analysis = _analyze_macro_with_llm(selected, df_ev)
            st.session_state[f"llm_result_{selected['session_id']}"] = analysis

    # LLM 분석 결과 — 전체 너비로 차트 하단에 표시
    result_key = f"llm_result_{selected['session_id']}"
    if result_key in st.session_state:
        st.markdown("**LLM 매크로 원인 분석 결과**")
        st.info(st.session_state[result_key])


# ─────────────────────────────────────────────
# LLM 매크로 원인 분석
# ─────────────────────────────────────────────

def _extract_mouse_features(df_ev: pd.DataFrame) -> dict:
    """이벤트 DataFrame에서 LLM 프롬프트용 주요 피처를 계산합니다."""
    df = df_ev.sort_values("timestamp").reset_index(drop=True)

    dt    = df["timestamp"].diff().fillna(0)
    dx    = df["screen_x"].diff().fillna(0)
    dy    = df["screen_y"].diff().fillna(0)
    dist  = np.sqrt(dx**2 + dy**2)

    safe_dt = dt.replace(0, np.nan)
    speed   = (dist / (safe_dt / 1000)).fillna(0)
    accel   = speed.diff().abs().fillna(0)
    angle   = np.arctan2(dy, dx)
    angle_diff = angle.diff().abs().fillna(0)

    click_rows = df[df["event_type"] == 5]
    click_dt   = click_rows["timestamp"].diff().dropna()

    total_disp = np.sqrt(
        (df["screen_x"].iloc[-1] - df["screen_x"].iloc[0])**2 +
        (df["screen_y"].iloc[-1] - df["screen_y"].iloc[0])**2
    )
    total_dist = dist.sum()
    linearity  = float(total_disp / (total_dist + 1e-9))
    dt_cv      = float(dt.std() / (dt.mean() + 1e-9))

    return {
        "speed_mean"          : round(float(speed.mean()), 2),
        "speed_std"           : round(float(speed.std()), 2),
        "speed_max"           : round(float(speed.max()), 2),
        "accel_mean"          : round(float(accel.mean()), 2),
        "curvature_mean"      : round(float(angle_diff.mean()), 4),
        "linearity"           : round(linearity, 4),
        "click_count"         : int(len(click_rows)),
        "click_interval_mean" : round(float(click_dt.mean()), 1) if len(click_dt) > 0 else 0,
        "click_interval_std"  : round(float(click_dt.std()), 1)  if len(click_dt) > 1 else 0,
        "dt_cv"               : round(dt_cv, 4),
        "session_duration_ms" : int(df["timestamp"].max() - df["timestamp"].min()),
        "event_count"         : len(df),
        "pause_count"         : int((dt > 200).sum()),
    }


def _analyze_macro_with_llm(session: dict, df_ev: pd.DataFrame) -> str:
    try:
        from utils.api import get_solar_client
        import streamlit as st

        api_key = st.secrets.get("UPSTAGE_API_KEY", "")
        if not api_key or api_key.startswith("up_xxx"):
            return "UPSTAGE_API_KEY가 설정되지 않았습니다. `.streamlit/secrets.toml`을 확인하세요."

        feats = _extract_mouse_features(df_ev)

        prompt = f"""다음은 마우스 매크로 탐지 모델이 매크로로 판정한 세션의 분석 데이터입니다.

## 판정 결과
- 매크로 확률: {session['probability'] * 100:.1f}%
- 신뢰도: {session['confidence'] * 100:.1f}%
- 총 이벤트 수: {session['event_count']}개
- 세션 시간: {feats['session_duration_ms']}ms

## 마우스 움직임 피처
- 평균 속도: {feats['speed_mean']} px/s (표준편차: {feats['speed_std']})
- 최대 속도: {feats['speed_max']} px/s
- 평균 가속도: {feats['accel_mean']}
- 평균 곡률 변화: {feats['curvature_mean']} (낮을수록 직선적)
- 직선성(linearity): {feats['linearity']} (1에 가까울수록 직선)
- 시간 간격 변동계수(dt_cv): {feats['dt_cv']} (낮을수록 일정한 간격)
- 일시정지 횟수(>200ms): {feats['pause_count']}

## 클릭 패턴
- 클릭 횟수: {feats['click_count']}
- 클릭 간격 평균: {feats['click_interval_mean']}ms (표준편차: {feats['click_interval_std']}ms)

위 데이터를 바탕으로, 이 세션이 매크로로 판정된 구체적인 이유를 3~5가지 항목으로 한국어로 설명해주세요. 각 항목은 어떤 수치가 이상하고, 정상 인간의 패턴과 어떻게 다른지 설명하세요."""

        client = get_solar_client()
        response = client.chat.completions.create(
            model="solar-pro",
            messages=[
                {"role": "system", "content": "당신은 사이버 보안 전문가로, 마우스 움직임 데이터를 분석하여 매크로/봇 여부를 판단하는 전문가입니다."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=800,
            temperature=0.3,
        )
        return response.choices[0].message.content

    except Exception as e:
        return f"분석 실패: {str(e)}"
