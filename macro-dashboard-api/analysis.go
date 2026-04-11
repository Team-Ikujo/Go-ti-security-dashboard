package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

const upstageBaseURL = "https://api.upstage.ai/v1/solar/chat/completions"

// ─────────────────────────────────────────────
// Upstage Solar API 클라이언트
// ─────────────────────────────────────────────

type upstageMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type upstageRequest struct {
	Model       string           `json:"model"`
	Messages    []upstageMessage `json:"messages"`
	MaxTokens   int              `json:"max_tokens"`
	Temperature float64          `json:"temperature"`
}

type upstageChoice struct {
	Message upstageMessage `json:"message"`
}

type upstageResponse struct {
	Choices []upstageChoice `json:"choices"`
	Error   *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func callUpstage(systemPrompt, userPrompt string) (string, error) {
	apiKey := os.Getenv("UPSTAGE_API_KEY")
	if apiKey == "" {
		return "", fmt.Errorf("UPSTAGE_API_KEY 환경변수가 설정되지 않았습니다")
	}

	body, _ := json.Marshal(upstageRequest{
		Model: "solar-pro",
		Messages: []upstageMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		MaxTokens:   900,
		Temperature: 0.3,
	})

	req, err := http.NewRequest(http.MethodPost, upstageBaseURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Upstage API 호출 실패: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Upstage API 오류 (status %d): %s", resp.StatusCode, string(raw))
	}

	var result upstageResponse
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("응답 파싱 실패: %w", err)
	}
	if result.Error != nil {
		return "", fmt.Errorf("Upstage 오류: %s", result.Error.Message)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("Upstage 응답에 choices가 없습니다")
	}
	return result.Choices[0].Message.Content, nil
}

// ─────────────────────────────────────────────
// 가드레일 이벤트 분석 프롬프트 생성
// ─────────────────────────────────────────────

func buildGuardrailPrompt(row guardrailAnalysisData) string {
	flags := []string{}
	if row.Webdriver {
		flags = append(flags, "Webdriver 감지")
	}
	if row.Headless {
		flags = append(flags, "Headless 브라우저")
	}
	if row.DevtoolsProto {
		flags = append(flags, "DevTools Protocol 활성")
	}

	flagStr := "없음"
	if len(flags) > 0 {
		flagStr = strings.Join(flags, ", ")
	}

	codeStr := "없음"
	if len(row.ReasonCodes) > 0 {
		codeStr = strings.Join(row.ReasonCodes, ", ")
	}

	return fmt.Sprintf(`다음은 가드레일 보안 시스템이 매크로/봇으로 판정하여 차단한 세션의 데이터입니다.

## 세션 정보
- Event ID: %s
- Session ID: %s
- IP 주소: %s
- 차단 시각: %s

## 탐지 지표
- 위험 점수: %.0f%%
- 탐지 사유 코드: %s
- 브라우저 이상 플래그: %s
- 플러그인 수: %d (정상 브라우저: 보통 3개 이상)
- 언어 설정 수: %d (정상 브라우저: 보통 2개 이상)

위 데이터를 분석해서 이 세션이 차단된 구체적인 이유를 3~5가지 항목으로 한국어로 설명해주세요.
각 항목에서 어떤 수치 또는 플래그가 비정상적이고, 정상 사용자 패턴과 어떻게 다른지 설명하세요.
마지막에는 이 세션이 자동화 도구(봇/매크로)일 가능성 평가를 한 줄로 요약하세요.`,
		row.EventID,
		row.SessionID,
		row.IPAddress,
		row.BlockedAt,
		float64(row.RiskScore),
		codeStr,
		flagStr,
		row.PluginsCount,
		row.LanguagesCount,
	)
}

// ─────────────────────────────────────────────
// 마우스 매크로 세션 분석 프롬프트 생성
// ─────────────────────────────────────────────

func buildMouseMacroPrompt(row mouseAnalysisData) string {
	return fmt.Sprintf(`다음은 마우스 매크로 탐지 모델이 매크로로 판정한 세션의 분석 데이터입니다.

## 판정 결과
- Session ID: %s
- 매크로 확률: %.1f%%
- 신뢰도: %.1f%%
- 총 이벤트 수: %d개
- 탐지 시각: %s

위 데이터를 분석해서 이 세션이 마우스 매크로로 판정된 이유를 3~5가지 항목으로 한국어로 설명해주세요.
높은 확률/신뢰도가 의미하는 바, 자동화된 마우스 움직임의 특징, 그리고 정상 사용자와의 차이점을 설명하세요.
마지막에는 이 세션의 위험도 평가를 한 줄로 요약하세요.`,
		row.SessionID,
		row.Probability*100,
		row.Confidence*100,
		row.EventCount,
		row.DetectedAt,
	)
}

// ─────────────────────────────────────────────
// DB 조회 헬퍼
// ─────────────────────────────────────────────

type guardrailAnalysisData struct {
	EventID        string
	SessionID      string
	IPAddress      string
	RiskScore      int
	ReasonCodes    []string
	Webdriver      bool
	Headless       bool
	DevtoolsProto  bool
	PluginsCount   int
	LanguagesCount int
	BlockedAt      string
}

type mouseAnalysisData struct {
	SessionID   string
	Probability float64
	Confidence  float64
	EventCount  int
	DetectedAt  string
}

func getGuardrailEventByID(eventID string) (*guardrailAnalysisData, error) {
	row := db.QueryRow(`
		SELECT event_id, session_id, ip_address, risk_score, reason_codes,
		       webdriver, headless, devtools_protocol, plugins_count, languages_count, blocked_at
		FROM blocked_events WHERE event_id = ?`, eventID)

	var (
		rcJSON                                 string
		webdriver, headless, devtoolsProto     int
		ipAddress                              sql.NullString
		riskScore                              float64
		d                                      guardrailAnalysisData
	)
	err := row.Scan(
		&d.EventID, &d.SessionID, &ipAddress,
		&riskScore, &rcJSON,
		&webdriver, &headless, &devtoolsProto,
		&d.PluginsCount, &d.LanguagesCount, &d.BlockedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	d.IPAddress = ipAddress.String
	d.RiskScore = int(riskScore * 100)
	d.Webdriver = webdriver == 1
	d.Headless = headless == 1
	d.DevtoolsProto = devtoolsProto == 1
	json.Unmarshal([]byte(rcJSON), &d.ReasonCodes)
	return &d, nil
}

func getMouseSessionByID(sessionID string) (*mouseAnalysisData, error) {
	row := db.QueryRow(`
		SELECT session_id, probability, confidence, event_count, detected_at
		FROM mouse_macro_sessions WHERE session_id = ?`, sessionID)

	var d mouseAnalysisData
	err := row.Scan(&d.SessionID, &d.Probability, &d.Confidence, &d.EventCount, &d.DetectedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &d, nil
}
