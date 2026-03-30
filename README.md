# 🛡️ Go-Ti Security Dashboard

**Go-Ti 매크로 탐지 보안 관제 시스템** — 야구 경기 티켓 예매 플랫폼을 대상으로 한 매크로(봇) 공격을 실시간으로 모니터링하고, AI 기반 분석 및 수동 심사를 통해 오탐률을 최소화하는 사후 처리 대시보드입니다.

> Streamlit 기반 웹 애플리케이션으로, AWS Cognito 인증, 보안 Agent, Grafana 연동을 지원합니다.

---

## 목차

- [주요 기능](#-주요-기능)
- [시스템 아키텍처](#-시스템-아키텍처)
- [시작하기](#-시작하기)
- [환경 변수 설정](#-환경-변수-설정)


---

## 주요 기능

### 1. 실시간 매크로 모니터링 대시보드
핵심 보안 지표를 한눈에 파악할 수 있는 메인 대시보드입니다.

| 기능 | 설명 |
|------|------|
| **핵심 지표 카드** | 금일 접속 건수, 접속자 수, 매크로 차단 건수, 차단율을 실시간 카드 UI로 표시 |
| **매크로 발생 국가 지도** | 국가별 매크로 탐지 현황 시각화 |
| **매크로 조치 현황** | Blocked / Pending / Warning / Passed 상태별 도넛 차트로 현재 조치 비율 표시 |
| **탐지 유형 통계** | Mouse Macro, API Abuse, Fast Click, Proxy IP 등 유형별 바 차트 |
| **에이전트 활동 이력** | AI 에이전트의 최근 분석 세션 이력을 카드 형태로 표시 |
| **최근 탐지 리스트** | 전체 탐지 이벤트를 테이블로 나열 (Risk Score 프로그레스 바 포함) |

### 2. AI 방어 어시스턴스 에이전트
Upstage Solar LLM을 활용한 대화형 보안 분석 에이전트입니다.

| 기능 | 설명 |
|------|------|
| **대화형 AI 분석** | 매크로 차단 이력 데이터를 기반으로 자연어 질의응답 |
| **스트리밍 응답** | AI Agent 응답을 실시간 스트리밍으로 출력 |
| **다중 세션 관리** | 분석 주제별로 독립된 대화 세션을 생성·관리 |
| **RAG 기반 응답** | GoTi 보안 정책과 Agent로 분석된 매크로 탐지 원인 리포트 DB(OpenSearch)를 통해 정확한 분석 제공 |

### 3. 의심 유저 수동 심사
AI 탐지 결과 중 관리자의 확인이 필요한 건을 직접 검토하는 화면입니다.

| 기능 | 설명 |
|------|------|
| **필터링 시스템** | 날짜, 대상 경기, 심사 상태별 다중 필터링으로 검토 대상 조회 |
| **매크로 탐지 원인 분석 리포트** | OpenSearch 기반 상세 분석 리포트를 모달로 표시 (위협 점수, 매칭 룰, 원본 로그) |
| **수동 차단 / 통과 처리** | 이벤트 건별 차단(Block) 또는 통과(Pass) 조치를 즉시 실행 |
| **전체 조치 현황 차트** | 글로벌 뷰로 전체적인 조치 분포를 시각화 |

### 4. Grafana 연동 모니터링
외부 Grafana 인스턴스와 연동하여 인프라 수준의 모니터링을 제공합니다.

| 기능 | 설명 |
|------|------|
| **대시보드 임베딩** | Grafana Public Dashboard를 iframe으로 직접 임베드 |

---

## 🏗 시스템 아키텍처

```
┌─────────────────────────────────────────────────────────┐
│                    Streamlit Cloud                       │
│  ┌─────────────────────────────────────────────────────┐ │
│  │                    app.py (Entry)                   │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ │ │
│  │  │Dashboard │ │ AI Agent │ │  Review  │ │Grafana │ │ │
│  │  │  View    │ │   View   │ │   View   │ │ View   │ │ │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └───┬────┘ │ │
│  │       │             │            │            │      │ │
│  │  ┌────┴─────────────┴────────────┴────────────┴────┐ │ │
│  │  │              Shared Components                  │ │ │
│  │  │   sidebar · header · charts · css_overrides     │ │ │
│  │  └────┬─────────────┬────────────┬────────────┬────┘ │ │
│  │       │             │            │            │      │ │
│  │  ┌────┴─────────────┴────────────┴────────────┴────┐ │ │
│  │  │               Utilities Layer                   │ │ │
│  │  │     auth · db · api · session                   │ │ │
│  │  └─────┬────────────┬────────────┬─────────────────┘ │ │
│  └────────┼────────────┼────────────┼───────────────────┘ │
│           │            │            │                     │
└───────────┼────────────┼────────────┼─────────────────────┘
            ▼            ▼            ▼
    ┌──────────┐  ┌────────────┐ ┌──────────────┐
    │  AWS     │  │  Upstage   │ │   Grafana    │
    │ Cognito  │  │ Solar LLM  │ │   Server     │
    │ (인증)    │  │ (AI 분석)   │ │   (모니터링)   │
    └──────────┘  └────────────┘ └──────────────┘
```

---

## 개발 세팅

### 사전 요구사항
- Python 3.9+
- (선택) AWS Cognito 사용자 풀 - 등록된 유저만 로그인 가능
- (선택) Upstage Solar API 키
- (선택) Grafana 서버 접속 정보

### 설치 및 실행

```bash
# 1. 레포지토리 클론
git clone https://github.com/Team-Ikujo/Go-ti-security-dashboard.git
cd Go-ti-security-dashboard

# 2. 의존성 설치
pip install -r requirements.txt

# 3. 시크릿 파일 생성
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
# secrets.toml 파일을 편집하여 API 키 등록

# 4. 앱 실행
streamlit run app.py
```

---

## 🔐 환경 변수 설정

`.streamlit/secrets.toml` 파일에 다음 항목을 설정합니다:

```toml
# AWS Cognito 인증 (미설정 시 테스트 모드)
COGNITO_USER_POOL_ID = "ap-northeast-2_XXXXXXXXX"
COGNITO_APP_CLIENT_ID = "your-app-client-id"
COGNITO_APP_CLIENT_SECRET = "your-app-client-secret"

# Upstage Solar LLM (AI 에이전트용)
UPSTAGE_API_KEY = "up_xxxxxxxxxxxxxxxxxxxxxxxx"

# Grafana 연동
GRAFANA_URL = "https://your-grafana-url"
GRAFANA_USERNAME = "admin"
GRAFANA_PASSWORD = "your-password"
GRAFANA_DASHBOARD_UID = "your-dashboard-uid"
GRAFANA_PUBLIC_DASHBOARD_URL = "https://your-grafana/public-dashboards/xxxxxx"
```

---

<p align="center">
  <b>Go-Ti Security Team</b> · Team Ikujo
</p>
