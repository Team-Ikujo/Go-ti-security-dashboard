package main

// ─────────────────────────────────────────────
// 요청 모델
// ─────────────────────────────────────────────

type BlockedEventRequest struct {
	SessionID        string   `json:"session_id"`
	UserID           *string  `json:"user_id,omitempty"`
	IPAddress        *string  `json:"ip_address,omitempty"`
	RiskScore        float64  `json:"risk_score"`
	ReasonCodes      []string `json:"reason_codes"`
	DetectionType    string   `json:"detection_type,omitempty"`
	Webdriver        bool     `json:"webdriver"`
	Headless         bool     `json:"headless"`
	DevtoolsProtocol bool     `json:"devtools_protocol"`
	PluginsCount     int      `json:"plugins_count"`
	LanguagesCount   int      `json:"languages_count"`
	BlockedAt        *string  `json:"blocked_at,omitempty"` // ISO 8601
}

type MouseEventItem struct {
	Timestamp int64   `json:"timestamp"`
	EventType int     `json:"event_type"`
	ScreenX   float64 `json:"screen_x"`
	ScreenY   float64 `json:"screen_y"`
}

type MouseMacroRequest struct {
	SessionID   string           `json:"session_id"`
	UserID      *string          `json:"user_id,omitempty"`
	Probability float64          `json:"probability"`
	Confidence  float64          `json:"confidence"`
	EventCount  int              `json:"event_count"`
	Events      []MouseEventItem `json:"events"`
}

type ActionRequest struct {
	Action string `json:"action"` // "Blocked" | "Passed"
}

// ─────────────────────────────────────────────
// 응답 모델
// ─────────────────────────────────────────────

type BlockedEventRow struct {
	EventID         string   `json:"event_id"`
	SessionID       string   `json:"session_id"`
	AccessDate      string   `json:"access_date"`
	AccessTime      string   `json:"access_time"`
	IPAddress       string   `json:"ip_address"`
	DetectionType   string   `json:"detection_type"`
	Status          string   `json:"status"`
	RiskScore       int      `json:"risk_score"`
	ReasonCodes     []string `json:"reason_codes"`
	UserID          string   `json:"user_id"`
	Webdriver       bool     `json:"webdriver"`
	Headless        bool     `json:"headless"`
	DevtoolsProto   bool     `json:"devtools_protocol"`
	PluginsCount    int      `json:"plugins_count"`
	LanguagesCount  int      `json:"languages_count"`
	BlockedAt       string   `json:"blocked_at"`
}

type MouseMacroSessionRow struct {
	SessionID   string           `json:"session_id"`
	UserID      string           `json:"user_id"`
	Probability float64          `json:"probability"`
	Confidence  float64          `json:"confidence"`
	EventCount  int              `json:"event_count"`
	Events      []MouseEventItem `json:"events"`
	DetectedAt  string           `json:"detected_at"`
}

type StatsSummary struct {
	TotalAccess      int     `json:"total_access"`
	TotalAccessDelta string  `json:"total_access_delta"`
	UniqueUsers      int     `json:"unique_users"`
	UniqueUsersDelta string  `json:"unique_users_delta"`
	BlockedCount     int     `json:"blocked_count"`
	BlockedDelta     string  `json:"blocked_delta"`
	BlockRate        float64 `json:"block_rate"`
	BlockRateDelta   string  `json:"block_rate_delta"`
	MouseMacroCount  int     `json:"mouse_macro_count"`
}

type DetectionTypeItem struct {
	Type  string `json:"type"`
	Count int    `json:"count"`
}

type HourlyTrendItem struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

type RiskDistributionItem struct {
	Range string `json:"range"`
	Count int    `json:"count"`
}

type DashboardOverview struct {
	Stats             StatsSummary           `json:"stats"`
	DetectionTypes    []DetectionTypeItem    `json:"detection_types"`
	HourlyTrend       []HourlyTrendItem      `json:"hourly_trend"`
	RiskDistribution  []RiskDistributionItem `json:"risk_distribution"`
	RecentGuardrail   []BlockedEventRow      `json:"recent_guardrail"`
	RecentMouseMacro  []MouseMacroSessionRow `json:"recent_mouse_macro"`
}

type AnalysisResponse struct {
	EventID  string `json:"event_id"`
	Analysis string `json:"analysis"`
}

type AlertItem struct {
	AlertID     string  `json:"alert_id"`
	SessionID   string  `json:"session_id"`
	UserID      string  `json:"user_id"`
	AlertType   string  `json:"alert_type"`
	Severity    string  `json:"severity"` // "critical" | "high" | "medium"
	RiskScore   int     `json:"risk_score"`
	Message     string  `json:"message"`
	TriggeredAt string  `json:"triggered_at"`
}
