import streamlit as st
from components.header import render_header
from data.provider import get_provider


def _build_detection_summary(provider) -> tuple[list[dict], str]:
    """가드레일 + 마우스 매크로 이벤트를 합쳐 LLM 프롬프트용 텍스트를 반환합니다."""
    events = []

    for e in provider.get_guardrail_events():
        events.append({
            "출처"      : "가드레일",
            "event_id"  : e.get("event_id", ""),
            "user_id"   : e.get("user_id") or "-",
            "ip_address": e.get("ip_address", ""),
            "risk_score": int(e.get("risk_score", 0) * 100),
            "reason_codes": ", ".join(e.get("reason_codes", [])),
            "webdriver" : e.get("webdriver", False),
            "headless"  : e.get("headless", False),
            "devtools"  : e.get("devtools_protocol", False),
            "plugins"   : e.get("plugins_count", 0),
            "languages" : e.get("languages_count", 0),
            "detected_at": (e.get("blocked_at", "")[:19] or "").replace("T", " "),
            "status"    : e.get("status", "Blocked"),
        })

    for s in provider.get_mouse_macro_sessions():
        events.append({
            "출처"      : "마우스 매크로",
            "event_id"  : s.get("session_id", "")[:20],
            "user_id"   : s.get("user_id") or "-",
            "ip_address": "-",
            "risk_score": int(s.get("probability", 0) * 100),
            "reason_codes": f"Mouse Macro (확률 {s.get('probability',0)*100:.1f}%, 신뢰도 {s.get('confidence',0)*100:.1f}%)",
            "webdriver" : False,
            "headless"  : False,
            "devtools"  : False,
            "plugins"   : 0,
            "languages" : 0,
            "detected_at": s.get("detected_at", "")[:19],
            "status"    : "Blocked",
        })

    if not events:
        return events, ""

    lines = ["다음은 최근 탐지된 의심 이벤트 목록입니다:\n"]
    for i, e in enumerate(events, 1):
        lines.append(
            f"{i}. [{e['출처']}] {e['event_id']} | User: {e['user_id']} | IP: {e['ip_address']} | "
            f"Risk: {e['risk_score']}점 | 사유: {e['reason_codes']} | 탐지: {e['detected_at']}"
        )
    return events, "\n".join(lines)


def _llm_review_analysis(event: dict, all_summary: str) -> str:
    try:
        import streamlit as st
        from utils.api import get_solar_client

        api_key = st.secrets.get("UPSTAGE_API_KEY", "")
        if not api_key or api_key.startswith("up_xxx"):
            return "UPSTAGE_API_KEY가 설정되지 않았습니다."

        prompt = f"""아래는 보안 탐지 시스템의 전체 이벤트 현황입니다:

{all_summary}

---
위 데이터에서 다음 이벤트에 대해 수동 심사 의견을 작성해주세요:

- 출처: {event['출처']}
- Event ID: {event['event_id']}
- User ID: {event['user_id']}
- IP 주소: {event['ip_address']}
- Risk Score: {event['risk_score']}점
- 탐지 사유: {event['reason_codes']}
- Webdriver: {event['webdriver']} / Headless: {event['headless']} / DevTools: {event['devtools']}
- 탐지 시각: {event['detected_at']}

다음 항목으로 간결하게 답변해주세요:
1. **판단**: 차단 유지 / 해제 권고 중 하나
2. **근거**: 위 데이터 기반으로 2~3문장
3. **추가 조치**: 필요한 경우 권고사항"""

        client = get_solar_client()
        resp = client.chat.completions.create(
            model="solar-pro",
            messages=[
                {"role": "system", "content": "당신은 사이버 보안 분석가입니다. 매크로 탐지 데이터를 바탕으로 의심 유저를 심사합니다."},
                {"role": "user", "content": prompt},
            ],
            max_tokens=500,
            temperature=0.2,
        )
        return resp.choices[0].message.content
    except Exception as ex:
        return f"분석 실패: {ex}"


def render_review():
    provider = get_provider()
    render_header("MANUAL REVIEW")
    st.header("의심 유저 수동 심사")
    st.write("탐지 시스템에서 수신된 가드레일·마우스 매크로 이벤트를 바탕으로 LLM이 심사 의견을 제공합니다.")
    st.markdown("<br>", unsafe_allow_html=True)

    events, summary_text = _build_detection_summary(provider)

    if not events:
        st.info("심사할 탐지 이벤트가 없습니다.")
        return

    # 필터
    sources = sorted({e["출처"] for e in events})
    statuses = sorted({e["status"] for e in events})
    col_f1, col_f2 = st.columns(2)
    with col_f1:
        sel_source = st.multiselect("출처 필터", sources, default=sources)
    with col_f2:
        sel_status = st.multiselect("상태 필터", statuses, default=statuses)

    filtered = [e for e in events if e["출처"] in sel_source and e["status"] in sel_status]

    if not filtered:
        st.success("필터 조건에 해당하는 이벤트가 없습니다.")
        return

    st.markdown("<br>", unsafe_allow_html=True)

    for event in filtered:
        with st.container(border=True):
            c1, c2, c3 = st.columns([1, 1, 1])
            with c1:
                st.caption("이벤트 정보")
                st.markdown(f"**출처:** `{event['출처']}`  \n**Event ID:** `{event['event_id']}`")
            with c2:
                st.caption("사용자 정보")
                st.markdown(f"**User ID:** `{event['user_id']}`  \n**IP:** `{event['ip_address']}`")
            with c3:
                st.caption("위험 지표")
                st.markdown(f"**Risk Score:** `{event['risk_score']}점`  \n**탐지:** {event['detected_at']}")

            st.caption(f"탐지 사유: {event['reason_codes']}")

            st.markdown("<br>", unsafe_allow_html=True)

            btn_col1, btn_col2, btn_col3 = st.columns(3)
            with btn_col1:
                if st.button("🤖 LLM 심사 의견 요청", key=f"llm_review_{event['event_id']}", width="stretch"):
                    with st.spinner("LLM 분석 중..."):
                        st.session_state[f"llm_review_result_{event['event_id']}"] = _llm_review_analysis(event, summary_text)
            with btn_col2:
                if st.button("🚫 수동 차단", key=f"block_{event['event_id']}", type="primary", width="stretch"):
                    provider.update_event_status(event["event_id"], "Blocked")
                    st.toast(f"✅ {event['event_id']} 차단 처리 완료", icon="🚨")
            with btn_col3:
                if st.button("✅ 통과 (Pass)", key=f"pass_{event['event_id']}", width="stretch"):
                    provider.update_event_status(event["event_id"], "Passed")
                    st.toast(f"✅ {event['event_id']} 통과 처리 완료")

            result_key = f"llm_review_result_{event['event_id']}"
            if result_key in st.session_state:
                st.markdown("**LLM 심사 의견**")
                st.info(st.session_state[result_key])
