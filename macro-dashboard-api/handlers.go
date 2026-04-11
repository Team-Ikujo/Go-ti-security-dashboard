package main

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
)

// ─────────────────────────────────────────────
// 공통 헬퍼
// ─────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func bindJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

func queryInt(r *http.Request, key string, defaultVal int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return v
}

// ─────────────────────────────────────────────
// Health
// ─────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ─────────────────────────────────────────────
// Guardrail Events
// ─────────────────────────────────────────────

// POST /api/v1/events/blocked
// 가드레일 서버에서 BLOCK 판정 세션을 수신합니다.
func handleReceiveBlockedEvent(w http.ResponseWriter, r *http.Request) {
	var req BlockedEventRequest
	if err := bindJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.SessionID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "session_id is required"})
		return
	}

	eventID, err := saveBlockedEvent(req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"accepted": true, "event_id": eventID})
}

// GET /api/v1/detections
// 가드레일 탐지 이벤트 목록을 반환합니다.
func handleGetDetections(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 200)
	events, err := listBlockedEvents(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, events)
}

// GET /api/v1/stats/summary
// 대시보드 상단 통계 카드용 요약 데이터를 반환합니다.
func handleGetStatsSummary(w http.ResponseWriter, r *http.Request) {
	total, err := getBlockedStats()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	mouseCount := 0
	db.QueryRow("SELECT COUNT(*) FROM mouse_macro_sessions").Scan(&mouseCount)

	blockRate := 0.0
	if total+mouseCount > 0 {
		blockRate = float64(total) / float64(total+mouseCount) * 100.0
	}

	writeJSON(w, http.StatusOK, StatsSummary{
		TotalAccess:      total + mouseCount,
		TotalAccessDelta: "+0",
		UniqueUsers:      total + mouseCount,
		UniqueUsersDelta: "+0",
		BlockedCount:     total,
		BlockedDelta:     "+0",
		BlockRate:        blockRate,
		BlockRateDelta:   "+0%",
		MouseMacroCount:  mouseCount,
	})
}

// POST /api/v1/interventions/{event_id}/action
// 수동 심사 결과(Block/Pass)를 업데이트합니다.
func handleUpdateAction(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	eventID := vars["event_id"]

	var req ActionRequest
	if err := bindJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Action != "Blocked" && req.Action != "Passed" && req.Action != "Pending" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "action must be Blocked, Passed, or Pending"})
		return
	}

	ok, err := updateEventStatus(eventID, req.Action)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "event not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": "status updated to " + req.Action,
	})
}

// ─────────────────────────────────────────────
// Mouse Macro Sessions
// ─────────────────────────────────────────────

// POST /api/v1/events/mouse-macro
// 마우스 매크로 탐지 서버에서 세션 데이터를 수신합니다.
func handleReceiveMouseMacro(w http.ResponseWriter, r *http.Request) {
	var req MouseMacroRequest
	if err := bindJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	sessionID, err := saveMouseMacroSession(req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"accepted": true, "session_id": sessionID})
}

// GET /api/v1/mouse-macro/sessions
// 마우스 매크로 세션 목록을 반환합니다.
func handleGetMouseMacroSessions(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)
	sessions, err := listMouseMacroSessions(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

// GET /api/v1/mouse-macro/sessions/{session_id}
// 특정 마우스 매크로 세션 상세를 반환합니다.
func handleGetMouseMacroSession(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["session_id"]

	sessions, err := listMouseMacroSessions(1000)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	for _, s := range sessions {
		if s.SessionID == sessionID {
			writeJSON(w, http.StatusOK, s)
			return
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
}

// ─────────────────────────────────────────────
// Analytics
// ─────────────────────────────────────────────

// GET /api/v1/analytics/detection-types
// 탐지 유형별 통계를 반환합니다.
func handleGetDetectionTypes(w http.ResponseWriter, r *http.Request) {
	items, err := getDetectionTypeStats()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

// GET /api/v1/analytics/hourly-trend
// 최근 24시간 시간대별 탐지 건수 트렌드를 반환합니다.
func handleGetHourlyTrend(w http.ResponseWriter, r *http.Request) {
	items, err := getHourlyTrend()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

// GET /api/v1/analytics/risk-distribution
// 위험도 구간별 분포를 반환합니다.
func handleGetRiskDistribution(w http.ResponseWriter, r *http.Request) {
	items, err := getRiskDistribution()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

// ─────────────────────────────────────────────
// Alerts
// ─────────────────────────────────────────────

// ─────────────────────────────────────────────
// AI 분석 (Upstage Solar)
// ─────────────────────────────────────────────

// POST /api/v1/analysis/guardrail/{event_id}
// 가드레일 차단 이벤트를 Upstage Solar로 분석합니다.
func handleAnalyzeGuardrail(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	eventID := vars["event_id"]

	data, err := getGuardrailEventByID(eventID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if data == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "event not found"})
		return
	}

	const sysPrompt = "당신은 사이버 보안 전문가로, 웹 매크로/봇 탐지 시스템의 차단 로그를 분석하여 차단 원인을 명확하게 설명하는 역할을 합니다."
	analysis, err := callUpstage(sysPrompt, buildGuardrailPrompt(*data))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, AnalysisResponse{EventID: eventID, Analysis: analysis})
}

// POST /api/v1/analysis/mouse-macro/{session_id}
// 마우스 매크로 세션을 Upstage Solar로 분석합니다.
func handleAnalyzeMouseMacro(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["session_id"]

	data, err := getMouseSessionByID(sessionID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if data == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}

	const sysPrompt = "당신은 사이버 보안 전문가로, 마우스 움직임 데이터를 분석하여 매크로/봇 여부를 판단하는 전문가입니다."
	analysis, err := callUpstage(sysPrompt, buildMouseMacroPrompt(*data))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, AnalysisResponse{EventID: sessionID, Analysis: analysis})
}

// GET /api/v1/alerts
// 고위험(risk_score >= 0.8) 활성 알림 목록을 반환합니다.
func handleGetAlerts(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 50)
	alerts, err := getAlerts(limit)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, alerts)
}

// ─────────────────────────────────────────────
// Dashboard Overview
// ─────────────────────────────────────────────

// GET /api/v1/dashboard/overview
// 프론트엔드 대시보드에 필요한 모든 데이터를 한 번에 반환합니다.
func handleGetDashboardOverview(w http.ResponseWriter, r *http.Request) {
	total, _ := getBlockedStats()
	mouseCount := 0
	db.QueryRow("SELECT COUNT(*) FROM mouse_macro_sessions").Scan(&mouseCount)

	blockRate := 0.0
	if total+mouseCount > 0 {
		blockRate = float64(total) / float64(total+mouseCount) * 100.0
	}

	detectionTypes, _ := getDetectionTypeStats()
	hourlyTrend, _ := getHourlyTrend()
	riskDist, _ := getRiskDistribution()
	recentGuardrail, _ := listBlockedEvents(10)
	recentMouse, _ := listMouseMacroSessions(5)

	writeJSON(w, http.StatusOK, DashboardOverview{
		Stats: StatsSummary{
			TotalAccess:      total + mouseCount,
			TotalAccessDelta: "+0",
			UniqueUsers:      total + mouseCount,
			UniqueUsersDelta: "+0",
			BlockedCount:     total,
			BlockedDelta:     "+0",
			BlockRate:        blockRate,
			BlockRateDelta:   "+0%",
			MouseMacroCount:  mouseCount,
		},
		DetectionTypes:   detectionTypes,
		HourlyTrend:      hourlyTrend,
		RiskDistribution: riskDist,
		RecentGuardrail:  recentGuardrail,
		RecentMouseMacro: recentMouse,
	})
}
