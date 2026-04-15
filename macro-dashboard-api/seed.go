package main

import (
	"encoding/json"
	"log"
	"math"
	"math/rand"
)

// seedDummyData DB가 비어 있을 때만 더미 데이터를 삽입합니다.
// INSERT OR IGNORE 를 사용하므로 중복 실행에 안전합니다.
func seedDummyData() {
	var count int
	db.QueryRow("SELECT COUNT(*) FROM blocked_events").Scan(&count)
	if count > 0 {
		log.Printf("[seed] DB에 이미 %d건의 데이터가 있습니다. 시딩을 건너뜁니다.", count)
		return
	}

	log.Println("[seed] DB가 비어 있습니다. 더미 데이터를 삽입합니다...")

	if err := seedGuardrailEvents(); err != nil {
		log.Printf("[seed] guardrail 삽입 오류: %v", err)
	}
	if err := seedMouseMacroSessions(); err != nil {
		log.Printf("[seed] mouse macro 삽입 오류: %v", err)
	}

	log.Println("[seed] 더미 데이터 삽입 완료.")
}

// ─────────────────────────────────────────────
// Guardrail 더미 이벤트 15건
// ─────────────────────────────────────────────

type seedGuardrailRow struct {
	eventID        string
	sessionID      string
	userID         string
	ipAddress      string
	riskScore      float64
	reasonCodes    []string
	detectionType  string
	webdriver      bool
	headless       bool
	devtools       bool
	pluginsCount   int
	languagesCount int
	blockedAt      string
	status         string
}

func seedGuardrailEvents() error {
	rows := []seedGuardrailRow{
		{"GR-1001", "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "user_20482", "203.242.89.166", 0.97, []string{"WEBDRIVER_DETECTED", "HEADLESS_BROWSER", "NO_PLUGINS"}, "정적 통계분석", true, true, false, 0, 1, "2026-04-15T09:11:22+00:00", "Blocked"},
		{"GR-1002", "b2c3d4e5-f6a7-8901-bcde-f12345678901", "user_38871", "115.68.22.44", 0.91, []string{"DEVTOOLS_PROTOCOL", "BHV_FAST_CLICK"}, "동적 행위분석", false, false, true, 2, 1, "2026-04-15T09:28:05+00:00", "Blocked"},
		{"GR-1003", "c3d4e5f6-a7b8-9012-cdef-123456789012", "", "91.108.4.200", 0.85, []string{"DATACENTER_IP", "BHV_RETRY_BURST"}, "LLM 심층분석", false, false, false, 5, 2, "2026-04-15T09:44:51+00:00", "Pending"},
		{"GR-1004", "d4e5f6a7-b8c9-0123-defa-234567890123", "user_55129", "58.229.10.83", 0.93, []string{"WEBDRIVER_DETECTED", "PRECHECK_FAIL", "NO_PLUGINS"}, "정적 통계분석", true, false, false, 0, 1, "2026-04-15T10:02:37+00:00", "Blocked"},
		{"GR-1005", "e5f6a7b8-c9d0-1234-efab-345678901234", "user_77340", "195.206.105.217", 0.62, []string{"BLACKLIST_IP"}, "블랙리스트", false, false, false, 8, 3, "2026-04-15T10:19:14+00:00", "Passed"},
		{"GR-1006", "f6a7b8c9-d0e1-2345-fabc-456789012345", "user_13024", "45.33.32.156", 0.88, []string{"HEADLESS_BROWSER", "BHV_FAST_CLICK", "NO_PLUGINS"}, "동적 행위분석", false, true, false, 0, 1, "2026-04-15T10:35:02+00:00", "Blocked"},
		{"GR-1007", "07b8c9d0-e1f2-3456-abcd-567890123456", "user_62801", "185.220.101.33", 0.79, []string{"DATACENTER_IP", "BHV_LINEAR_MOUSE"}, "동적 행위분석", false, false, false, 3, 1, "2026-04-15T10:51:48+00:00", "Blocked"},
		{"GR-1008", "18c9d0e1-f2a3-4567-bcde-678901234567", "", "159.89.123.45", 0.95, []string{"WEBDRIVER_DETECTED", "DEVTOOLS_PROTOCOL", "HEADLESS_BROWSER"}, "정적 통계분석", true, true, true, 0, 1, "2026-04-15T11:07:33+00:00", "Blocked"},
		{"GR-1009", "29d0e1f2-a3b4-5678-cdef-789012345678", "user_49037", "104.21.67.89", 0.71, []string{"BHV_RETRY_BURST", "PRECHECK_FAIL"}, "동적 행위분석", false, false, false, 6, 2, "2026-04-15T11:24:19+00:00", "Pending"},
		{"GR-1010", "3ae1f2a3-b4c5-6789-defa-890123456789", "user_81453", "172.67.45.123", 0.83, []string{"CREDENTIAL_STUFFING", "BHV_FAST_CLICK"}, "동적 행위분석", false, false, false, 4, 2, "2026-04-15T11:40:55+00:00", "Blocked"},
		{"GR-1011", "4bf2a3b4-c5d6-7890-efab-901234567890", "user_30276", "134.209.88.11", 0.68, []string{"BLACKLIST_IP", "DATACENTER_IP"}, "블랙리스트", false, false, false, 7, 3, "2026-04-15T11:57:41+00:00", "Blocked"},
		{"GR-1012", "5ca3b4c5-d6e7-8901-fabc-012345678901", "user_97614", "167.71.55.200", 0.99, []string{"WEBDRIVER_DETECTED", "HEADLESS_BROWSER", "DEVTOOLS_PROTOCOL", "NO_PLUGINS"}, "정적 통계분석", true, true, true, 0, 1, "2026-04-15T12:13:08+00:00", "Blocked"},
		{"GR-1013", "6db4c5d6-e7f8-9012-abcd-123456789012", "", "95.216.44.77", 0.76, []string{"BHV_LINEAR_MOUSE", "BHV_FAST_CLICK"}, "동적 행위분석", false, false, false, 2, 1, "2026-04-15T12:29:54+00:00", "Pending"},
		{"GR-1014", "7ec5d6e7-f8a9-0123-bcde-234567890123", "user_53892", "1.234.56.78", 0.57, []string{"PRECHECK_FAIL"}, "정적 통계분석", false, false, false, 9, 4, "2026-04-15T12:46:30+00:00", "Passed"},
		{"GR-1015", "8fd6e7f8-a9b0-1234-cdef-345678901234", "user_18745", "103.45.67.89", 0.90, []string{"WEBDRIVER_DETECTED", "BHV_RETRY_BURST"}, "동적 행위분석", true, false, false, 1, 1, "2026-04-15T13:03:17+00:00", "Blocked"},
	}

	stmt, err := db.Prepare(`
		INSERT OR IGNORE INTO blocked_events
			(event_id, session_id, user_id, ip_address, risk_score,
			 reason_codes, detection_type, webdriver, headless, devtools_protocol,
			 plugins_count, languages_count, blocked_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range rows {
		rcJSON, _ := json.Marshal(r.reasonCodes)
		_, err := stmt.Exec(
			r.eventID, r.sessionID, r.userID, r.ipAddress, r.riskScore,
			string(rcJSON), r.detectionType,
			boolToInt(r.webdriver), boolToInt(r.headless), boolToInt(r.devtools),
			r.pluginsCount, r.languagesCount, r.blockedAt, r.status,
		)
		if err != nil {
			log.Printf("[seed] guardrail insert error (%s): %v", r.eventID, err)
		}
	}
	return nil
}

// ─────────────────────────────────────────────
// Mouse Macro 더미 세션 7건
// ─────────────────────────────────────────────

type seedMacroRow struct {
	sessionID   string
	userID      string
	probability float64
	confidence  float64
	eventCount  int
	detectedAt  string
	seed        int64
}

func seedMouseMacroSessions() error {
	rows := []seedMacroRow{
		{"MS-7f3a9c12-4e8b-4d1f-9abc-23456789abcd", "user_83021", 0.97, 0.93, 312, "2026-04-15T09:23:11+00:00", 1},
		{"MS-2b5d8e34-7c1a-4f92-b0de-98765432dcba", "user_44190", 0.91, 0.87, 228, "2026-04-15T10:05:42+00:00", 2},
		{"MS-c9e12345-6789-4abc-def0-1234567890ef", "", 0.85, 0.79, 180, "2026-04-15T10:48:05+00:00", 3},
		{"MS-a1b2c3d4-e5f6-4789-0abc-def012345678", "user_61407", 0.78, 0.72, 154, "2026-04-15T11:31:29+00:00", 4},
		{"MS-f0e9d8c7-b6a5-4432-9876-543210fedcba", "user_29354", 0.94, 0.90, 275, "2026-04-15T12:14:57+00:00", 5},
		{"MS-e3d2c1b0-a9f8-4321-8765-432109876543", "user_72018", 0.88, 0.83, 196, "2026-04-15T12:58:33+00:00", 6},
		{"MS-b7a6f5e4-d3c2-4b1a-0987-654321098765", "user_50391", 0.82, 0.76, 143, "2026-04-15T13:41:08+00:00", 7},
	}

	stmt, err := db.Prepare(`
		INSERT OR IGNORE INTO mouse_macro_sessions
			(session_id, user_id, probability, confidence, event_count, events_json, detected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range rows {
		events := generateMouseEvents(r.seed, r.eventCount)
		eventsJSON, _ := json.Marshal(events)
		_, err := stmt.Exec(
			r.sessionID, r.userID, r.probability, r.confidence,
			r.eventCount, string(eventsJSON), r.detectedAt,
		)
		if err != nil {
			log.Printf("[seed] mouse macro insert error (%s): %v", r.sessionID, err)
		}
	}
	return nil
}

// generateMouseEvents seed 기반으로 마우스 이벤트 배열을 생성합니다.
// 매크로 특성: 이동 간격이 매우 일정하고 경로가 직선적입니다.
func generateMouseEvents(seed int64, count int) []MouseEventItem {
	rng := rand.New(rand.NewSource(seed))

	baseTS := int64(1744700000000) + rng.Int63n(7_200_000)
	x := float64(200 + rng.Intn(1200))
	y := float64(150 + rng.Intn(700))

	// 이벤트 타입 가중치: Move(2) 50%, Click(5) 27%, Drag(4) 10%, Wheel(3) 8%, Release(1) 5%
	typeWeights := []struct {
		etype  int
		cumul  float64
	}{
		{2, 0.50},
		{5, 0.77},
		{4, 0.87},
		{3, 0.95},
		{1, 1.00},
	}

	pickType := func() int {
		f := rng.Float64()
		for _, w := range typeWeights {
			if f < w.cumul {
				return w.etype
			}
		}
		return 2
	}

	events := make([]MouseEventItem, 0, count)
	ts := baseTS
	for i := 0; i < count; i++ {
		etype := pickType()

		var interval int64
		if etype == 2 {
			interval = 8 + rng.Int63n(5) // 8~12ms: 매우 일정한 간격 (매크로 특성)
		} else {
			interval = 14 + rng.Int63n(15) // 14~28ms
		}
		ts += interval

		if etype == 2 {
			x = clamp(x+float64(rng.Intn(9)-4), 0, 1920) // ±4px 미세 이동 (직선에 가까움)
			y = clamp(y+float64(rng.Intn(7)-3), 0, 1080)
		}

		events = append(events, MouseEventItem{
			Timestamp: ts,
			EventType: etype,
			ScreenX:   math.Round(x),
			ScreenY:   math.Round(y),
		})
	}
	return events
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
