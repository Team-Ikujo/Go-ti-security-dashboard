package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
)

func main() {
	// distroless HEALTHCHECK 용: -healthcheck 플래그로 실행 시 /health 호출 후 종료
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		port := os.Getenv("PORT")
		if port == "" {
			port = "8200"
		}
		resp, err := http.Get(fmt.Sprintf("http://localhost:%s/health", port))
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}

	// DB 초기화 (Python server와 동일한 blocked_events.db 공유)
	initDB()
	// DB가 비어 있을 때만 더미 데이터 삽입 (PVC 첫 마운트 시 자동 시딩)
	seedDummyData()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8200"
	}

	r := mux.NewRouter()
	r.Use(corsMiddleware)
	r.Use(loggingMiddleware)

	// ── Health ────────────────────────────────
	r.HandleFunc("/health", handleHealth).Methods(http.MethodGet)

	api := r.PathPrefix("/api/v1").Subrouter()

	// ── Dashboard Overview (프론트엔드 단일 호출용) ──
	api.HandleFunc("/dashboard/overview", handleGetDashboardOverview).Methods(http.MethodGet)

	// ── Stats ────────────────────────────────
	api.HandleFunc("/stats/summary", handleGetStatsSummary).Methods(http.MethodGet)

	// ── Guardrail Events ──────────────────────
	// 가드레일 서버 → POST (가드레일 서버가 BLOCK 판정 데이터를 전송)
	api.HandleFunc("/events/blocked", handleReceiveBlockedEvent).Methods(http.MethodPost)
	// 대시보드 프론트 → GET (탐지 이벤트 목록 조회)
	api.HandleFunc("/detections", handleGetDetections).Methods(http.MethodGet)
	// 수동 심사 액션 업데이트
	api.HandleFunc("/interventions/{event_id}/action", handleUpdateAction).Methods(http.MethodPost)

	// ── Mouse Macro Sessions ──────────────────
	// 마우스 ML 서버 → POST (매크로 판정 세션 데이터 전송)
	api.HandleFunc("/events/mouse-macro", handleReceiveMouseMacro).Methods(http.MethodPost)
	// 대시보드 프론트 → GET (세션 목록 조회)
	api.HandleFunc("/mouse-macro/sessions", handleGetMouseMacroSessions).Methods(http.MethodGet)
	// 특정 세션 상세 조회
	api.HandleFunc("/mouse-macro/sessions/{session_id}", handleGetMouseMacroSession).Methods(http.MethodGet)

	// ── Analytics ────────────────────────────
	api.HandleFunc("/analytics/detection-types", handleGetDetectionTypes).Methods(http.MethodGet)
	api.HandleFunc("/analytics/hourly-trend", handleGetHourlyTrend).Methods(http.MethodGet)
	api.HandleFunc("/analytics/risk-distribution", handleGetRiskDistribution).Methods(http.MethodGet)

	// ── Alerts ───────────────────────────────
	api.HandleFunc("/alerts", handleGetAlerts).Methods(http.MethodGet)

	// ── AI 분석 (Upstage Solar) ───────────────
	api.HandleFunc("/analysis/guardrail/{event_id}", handleAnalyzeGuardrail).Methods(http.MethodPost)
	api.HandleFunc("/analysis/mouse-macro/{session_id}", handleAnalyzeMouseMacro).Methods(http.MethodPost)
	api.HandleFunc("/analysis/ip/{ip_address}", handleAnalyzeIP).Methods(http.MethodPost)
	api.HandleFunc("/analysis/ip-summary", handleGetIPSummary).Methods(http.MethodGet)

	srv := &http.Server{
		Addr:         "0.0.0.0:" + port,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("[server] macro-dashboard-api listening on :%s", port)
	log.Printf("[server] shared DB: %s", dbPath())
	log.Printf("[server] API endpoints:")
	log.Printf("  GET  /health")
	log.Printf("  GET  /api/v1/dashboard/overview")
	log.Printf("  GET  /api/v1/stats/summary")
	log.Printf("  POST /api/v1/events/blocked        ← guardrail server")
	log.Printf("  GET  /api/v1/detections")
	log.Printf("  POST /api/v1/interventions/{id}/action")
	log.Printf("  POST /api/v1/events/mouse-macro    ← mouse-ml server")
	log.Printf("  GET  /api/v1/mouse-macro/sessions")
	log.Printf("  GET  /api/v1/mouse-macro/sessions/{id}")
	log.Printf("  GET  /api/v1/analytics/detection-types")
	log.Printf("  GET  /api/v1/analytics/hourly-trend")
	log.Printf("  GET  /api/v1/analytics/risk-distribution")
	log.Printf("  GET  /api/v1/alerts")
	log.Printf("  POST /api/v1/analysis/guardrail/{event_id}   ← Upstage Solar 분석")
	log.Printf("  POST /api/v1/analysis/mouse-macro/{session_id} ← Upstage Solar 분석")
	log.Printf("  POST /api/v1/analysis/ip/{ip_address}        ← IP 종합 분석")
	log.Printf("  GET  /api/v1/analysis/ip-summary             ← IP별 탐지 요약")

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[server] error: %v", err)
	}
}

// ─────────────────────────────────────────────
// Middleware
// ─────────────────────────────────────────────

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(lw, r)
		log.Printf("[%s] %s %s %d (%v)", r.Method, r.URL.Path, r.RemoteAddr, lw.statusCode, time.Since(start))
	})
}

type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (lw *loggingResponseWriter) WriteHeader(code int) {
	lw.statusCode = code
	lw.ResponseWriter.WriteHeader(code)
}
