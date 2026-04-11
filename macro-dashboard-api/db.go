package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var db *sql.DB

// dbPath returns the path to the shared SQLite DB file.
// Reads DATABASE_DIR env (same as Python server), defaults to parent directory.
func dbPath() string {
	dir := os.Getenv("DATABASE_DIR")
	if dir == "" {
		// macro-dashboard-api/ 의 상위 디렉토리 (프로젝트 루트)
		exe, err := os.Getwd()
		if err != nil {
			exe = "."
		}
		dir = filepath.Dir(exe)
	}
	return filepath.Join(dir, "blocked_events.db")
}

func initDB() {
	path := dbPath()
	log.Printf("[db] using database at %s", path)

	var err error
	db, err = sql.Open("sqlite", path)
	if err != nil {
		log.Fatalf("db open error: %v", err)
	}
	db.SetMaxOpenConns(1) // SQLite는 단일 연결 권장

	// 테이블 생성 (Python server와 동일한 스키마)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS blocked_events (
			id                INTEGER PRIMARY KEY AUTOINCREMENT,
			event_id          TEXT UNIQUE,
			session_id        TEXT NOT NULL,
			user_id           TEXT,
			ip_address        TEXT,
			risk_score        REAL,
			reason_codes      TEXT,
			webdriver         INTEGER,
			headless          INTEGER,
			devtools_protocol INTEGER,
			plugins_count     INTEGER,
			languages_count   INTEGER,
			blocked_at        TEXT,
			status            TEXT DEFAULT 'Blocked'
		)
	`)
	if err != nil {
		log.Fatalf("create blocked_events table: %v", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS mouse_macro_sessions (
			id          INTEGER PRIMARY KEY AUTOINCREMENT,
			session_id  TEXT UNIQUE,
			user_id     TEXT,
			probability REAL,
			confidence  REAL,
			event_count INTEGER,
			events_json TEXT,
			detected_at TEXT
		)
	`)
	if err != nil {
		log.Fatalf("create mouse_macro_sessions table: %v", err)
	}

	// 마이그레이션: user_id 컬럼 없으면 추가
	db.Exec("ALTER TABLE mouse_macro_sessions ADD COLUMN user_id TEXT")
}

// ─────────────────────────────────────────────
// Guardrail (blocked_events)
// ─────────────────────────────────────────────

func saveBlockedEvent(req BlockedEventRequest) (string, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	eventID := req.SessionID
	if eventID == "" {
		eventID = fmt.Sprintf("GR-%d", time.Now().UnixMilli())
	} else {
		eventID = fmt.Sprintf("GR-%d", time.Now().UnixMilli())
	}

	reasonJSON, _ := json.Marshal(req.ReasonCodes)

	blockedAt := now
	if req.BlockedAt != nil && *req.BlockedAt != "" {
		blockedAt = *req.BlockedAt
	}

	userID := ""
	if req.UserID != nil {
		userID = *req.UserID
	}
	ipAddress := ""
	if req.IPAddress != nil {
		ipAddress = *req.IPAddress
	}

	_, err := db.Exec(`
		INSERT OR IGNORE INTO blocked_events
			(event_id, session_id, user_id, ip_address, risk_score,
			 reason_codes, webdriver, headless, devtools_protocol,
			 plugins_count, languages_count, blocked_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Blocked')
	`,
		eventID,
		req.SessionID,
		userID,
		ipAddress,
		req.RiskScore,
		string(reasonJSON),
		boolToInt(req.Webdriver),
		boolToInt(req.Headless),
		boolToInt(req.DevtoolsProtocol),
		req.PluginsCount,
		req.LanguagesCount,
		blockedAt,
	)
	return eventID, err
}

func listBlockedEvents(limit int) ([]BlockedEventRow, error) {
	rows, err := db.Query(
		"SELECT * FROM blocked_events ORDER BY id DESC LIMIT ?", limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []BlockedEventRow
	for rows.Next() {
		var (
			id, pluginsCount, languagesCount, webdriver, headless, devtoolsProto int
			eventID, sessionID, blockedAt, status, reasonCodesJSON               string
			userID, ipAddress                                                      sql.NullString
			riskScore                                                              float64
		)
		if err := rows.Scan(&id, &eventID, &sessionID, &userID, &ipAddress,
			&riskScore, &reasonCodesJSON, &webdriver, &headless,
			&devtoolsProto, &pluginsCount, &languagesCount, &blockedAt, &status); err != nil {
			continue
		}

		var reasonCodes []string
		json.Unmarshal([]byte(reasonCodesJSON), &reasonCodes)

		datePart := ""
		timePart := ""
		if len(blockedAt) >= 10 {
			datePart = blockedAt[:10]
		}
		if len(blockedAt) >= 19 {
			timePart = blockedAt[11:19]
		}

		result = append(result, BlockedEventRow{
			EventID:        eventID,
			SessionID:      sessionID,
			AccessDate:     datePart,
			AccessTime:     timePart,
			IPAddress:      ipAddress.String,
			DetectionType:  reasonToDetectionType(reasonCodes),
			Status:         status,
			RiskScore:      int(riskScore * 100),
			ReasonCodes:    reasonCodes,
			UserID:         userID.String,
			Webdriver:      webdriver == 1,
			Headless:       headless == 1,
			DevtoolsProto:  devtoolsProto == 1,
			PluginsCount:   pluginsCount,
			LanguagesCount: languagesCount,
			BlockedAt:      blockedAt,
		})
	}
	if result == nil {
		result = []BlockedEventRow{}
	}
	return result, nil
}

func getBlockedStats() (total int, err error) {
	err = db.QueryRow("SELECT COUNT(*) FROM blocked_events").Scan(&total)
	return
}

func updateEventStatus(eventID, newStatus string) (bool, error) {
	res, err := db.Exec(
		"UPDATE blocked_events SET status = ? WHERE event_id = ?",
		newStatus, eventID,
	)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ─────────────────────────────────────────────
// Mouse Macro Sessions
// ─────────────────────────────────────────────

func saveMouseMacroSession(req MouseMacroRequest) (string, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	sessionID := req.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("MS-%d", time.Now().UnixMilli())
	}

	eventsJSON, _ := json.Marshal(req.Events)

	userID := ""
	if req.UserID != nil {
		userID = *req.UserID
	}

	_, err := db.Exec(`
		INSERT OR IGNORE INTO mouse_macro_sessions
			(session_id, user_id, probability, confidence, event_count, events_json, detected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`,
		sessionID,
		userID,
		req.Probability,
		req.Confidence,
		req.EventCount,
		string(eventsJSON),
		now,
	)
	return sessionID, err
}

func listMouseMacroSessions(limit int) ([]MouseMacroSessionRow, error) {
	rows, err := db.Query(
		"SELECT session_id, user_id, probability, confidence, event_count, events_json, detected_at FROM mouse_macro_sessions ORDER BY id DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []MouseMacroSessionRow
	for rows.Next() {
		var (
			sessionID, eventsJSON, detectedAt string
			userID                             sql.NullString
			probability, confidence            float64
			eventCount                         int
		)
		if err := rows.Scan(&sessionID, &userID, &probability, &confidence, &eventCount, &eventsJSON, &detectedAt); err != nil {
			continue
		}

		var events []MouseEventItem
		json.Unmarshal([]byte(eventsJSON), &events)
		if events == nil {
			events = []MouseEventItem{}
		}

		result = append(result, MouseMacroSessionRow{
			SessionID:   sessionID,
			UserID:      userID.String,
			Probability: probability,
			Confidence:  confidence,
			EventCount:  eventCount,
			Events:      events,
			DetectedAt:  detectedAt,
		})
	}
	if result == nil {
		result = []MouseMacroSessionRow{}
	}
	return result, nil
}

// ─────────────────────────────────────────────
// Analytics
// ─────────────────────────────────────────────

func getDetectionTypeStats() ([]DetectionTypeItem, error) {
	rows, err := db.Query("SELECT reason_codes FROM blocked_events")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var rc string
		rows.Scan(&rc)
		var codes []string
		json.Unmarshal([]byte(rc), &codes)
		dt := reasonToDetectionType(codes)
		counts[dt]++
	}

	result := []DetectionTypeItem{}
	for k, v := range counts {
		result = append(result, DetectionTypeItem{Type: k, Count: v})
	}
	return result, nil
}

func getHourlyTrend() ([]HourlyTrendItem, error) {
	// 최근 24시간 시간별 blocked_events 집계
	rows, err := db.Query(`
		SELECT substr(blocked_at, 12, 2) AS hour, COUNT(*) AS cnt
		FROM blocked_events
		WHERE blocked_at >= datetime('now', '-24 hours')
		GROUP BY hour
		ORDER BY hour
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := []HourlyTrendItem{}
	for rows.Next() {
		var item HourlyTrendItem
		rows.Scan(&item.Hour, &item.Count)
		result = append(result, item)
	}

	// mouse_macro_sessions도 합산
	mouseRows, err := db.Query(`
		SELECT substr(detected_at, 12, 2) AS hour, COUNT(*) AS cnt
		FROM mouse_macro_sessions
		WHERE detected_at >= datetime('now', '-24 hours')
		GROUP BY hour
		ORDER BY hour
	`)
	if err == nil {
		defer mouseRows.Close()
		for mouseRows.Next() {
			var item HourlyTrendItem
			mouseRows.Scan(&item.Hour, &item.Count)
			// 이미 존재하는 시간대면 합산
			found := false
			for i := range result {
				if result[i].Hour == item.Hour {
					result[i].Count += item.Count
					found = true
					break
				}
			}
			if !found {
				result = append(result, item)
			}
		}
	}
	return result, nil
}

func getRiskDistribution() ([]RiskDistributionItem, error) {
	type rangeSpec struct {
		label string
		min   float64
		max   float64
	}
	ranges := []rangeSpec{
		{"0–20", 0, 0.20},
		{"21–40", 0.20, 0.40},
		{"41–60", 0.40, 0.60},
		{"61–80", 0.60, 0.80},
		{"81–100", 0.80, 1.01},
	}

	result := []RiskDistributionItem{}
	for _, r := range ranges {
		var cnt int
		db.QueryRow(
			"SELECT COUNT(*) FROM blocked_events WHERE risk_score >= ? AND risk_score < ?",
			r.min, r.max,
		).Scan(&cnt)
		result = append(result, RiskDistributionItem{Range: r.label, Count: cnt})
	}
	return result, nil
}

func getAlerts(limit int) ([]AlertItem, error) {
	// risk_score > 0.8 이고 status = 'Blocked' 인 고위험 이벤트를 알림으로 반환
	rows, err := db.Query(`
		SELECT event_id, session_id, user_id, ip_address, risk_score, reason_codes, blocked_at
		FROM blocked_events
		WHERE risk_score >= 0.8 AND status = 'Blocked'
		ORDER BY id DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []AlertItem
	for rows.Next() {
		var (
			eventID, sessionID, blockedAt, reasonCodesJSON string
			userID, ipAddress                               sql.NullString
			riskScore                                       float64
		)
		if err := rows.Scan(&eventID, &sessionID, &userID, &ipAddress, &riskScore, &reasonCodesJSON, &blockedAt); err != nil {
			continue
		}

		var codes []string
		json.Unmarshal([]byte(reasonCodesJSON), &codes)

		severity := "high"
		if riskScore >= 0.95 {
			severity = "critical"
		}

		result = append(result, AlertItem{
			AlertID:     "ALT-" + eventID,
			SessionID:   sessionID,
			UserID:      userID.String,
			AlertType:   reasonToDetectionType(codes),
			Severity:    severity,
			RiskScore:   int(riskScore * 100),
			Message:     fmt.Sprintf("고위험 세션 탐지: %s (사유: %s)", sessionID[:min(16, len(sessionID))], strings.Join(codes, ", ")),
			TriggeredAt: blockedAt,
		})
	}
	if result == nil {
		result = []AlertItem{}
	}
	return result, nil
}

// ─────────────────────────────────────────────
// 내부 헬퍼
// ─────────────────────────────────────────────

func reasonToDetectionType(codes []string) string {
	for _, code := range codes {
		c := strings.ToUpper(code)
		if strings.Contains(c, "PRECHECK") || strings.Contains(c, "WEBDRIVER") || strings.Contains(c, "HEADLESS") {
			return "정적 통계분석"
		}
		if strings.Contains(c, "BHV") || strings.Contains(c, "BEHAVIOR") || strings.Contains(c, "RETRY") || strings.Contains(c, "CLICK") {
			return "동적 행위분석"
		}
		if strings.Contains(c, "NET") || strings.Contains(c, "NETWORK") || strings.Contains(c, "BURST") || strings.Contains(c, "DATACENTER") {
			return "LLM 심층분석"
		}
		if strings.Contains(c, "BLACKLIST") {
			return "블랙리스트"
		}
	}
	return "동적 행위분석"
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
