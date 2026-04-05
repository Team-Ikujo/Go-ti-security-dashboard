"""
가드레일 서버에서 전송된 BLOCK 이벤트를 SQLite에 저장/조회하는 헬퍼 모듈.
"""
import json
import os
import sqlite3
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "blocked_events.db")


def init_blocked_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocked_events (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id          TEXT UNIQUE,
            session_id        TEXT NOT NULL,
            user_id           TEXT,
            ip_address        TEXT,
            risk_score        REAL,
            reason_codes      TEXT,   -- JSON 배열 문자열
            webdriver         INTEGER,
            headless          INTEGER,
            devtools_protocol INTEGER,
            plugins_count     INTEGER,
            languages_count   INTEGER,
            blocked_at        TEXT,   -- ISO 8601
            status            TEXT DEFAULT 'Blocked'
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mouse_macro_sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT UNIQUE,
            user_id     TEXT,
            probability REAL,
            confidence  REAL,
            event_count INTEGER,
            events_json TEXT,   -- JSON 배열 (MouseEvent 객체 배열)
            detected_at TEXT    -- ISO 8601
        )
    """)
    # 기존 테이블에 user_id 컬럼 없으면 추가 (마이그레이션)
    try:
        conn.execute("ALTER TABLE mouse_macro_sessions ADD COLUMN user_id TEXT")
        conn.commit()
    except Exception:
        pass  # 이미 존재하면 무시

    conn.commit()
    conn.close()


def save_blocked_event(event: dict) -> str:
    """
    이벤트를 저장하고 생성된 event_id를 반환합니다.
    session_id 중복 시 IGNORE (동일 세션 중복 저장 방지).
    """
    conn = sqlite3.connect(DB_PATH)
    now = datetime.now(timezone.utc).isoformat()
    event_id = event.get("event_id") or f"GR-{int(datetime.now().timestamp() * 1000)}"

    conn.execute(
        """
        INSERT OR IGNORE INTO blocked_events
            (event_id, session_id, user_id, ip_address, risk_score,
             reason_codes, webdriver, headless, devtools_protocol,
             plugins_count, languages_count, blocked_at, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Blocked')
        """,
        (
            event_id,
            event.get("session_id", ""),
            event.get("user_id"),
            event.get("ip_address", ""),
            event.get("risk_score", 0.0),
            json.dumps(event.get("reason_codes", [])),
            int(event.get("webdriver", False)),
            int(event.get("headless", False)),
            int(event.get("devtools_protocol", False)),
            event.get("plugins_count", 0),
            event.get("languages_count", 0),
            event.get("blocked_at") or now,
        ),
    )
    conn.commit()
    conn.close()
    return event_id


def list_blocked_events(limit: int = 200) -> list[dict]:
    """최근 blocked_events를 대시보드 탐지 리스트 형식으로 반환합니다."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM blocked_events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()

    result = []
    for row in rows:
        blocked_at = row["blocked_at"] or ""
        date_part = blocked_at[:10] if len(blocked_at) >= 10 else ""
        time_part = blocked_at[11:19] if len(blocked_at) >= 19 else ""

        try:
            reason_codes = json.loads(row["reason_codes"] or "[]")
        except Exception:
            reason_codes = []

        detection_type = _reason_to_detection_type(reason_codes)
        risk_score_pct = int(round((row["risk_score"] or 0.0) * 100))

        result.append({
            "event_id": row["event_id"],
            "session_id": row["session_id"],
            "access_date": date_part,
            "access_time": time_part,
            "game_title": "",
            "ip_address": row["ip_address"] or "",
            "target_url": "",
            "detection_type": detection_type,
            "status": row["status"],
            "risk_score": risk_score_pct,
            "reason_codes": reason_codes,
        })
    return result


def get_blocked_stats() -> dict:
    conn = sqlite3.connect(DB_PATH)
    total = conn.execute("SELECT COUNT(*) FROM blocked_events").fetchone()[0]
    conn.close()
    return {"total": total}


def update_event_status(event_id: str, new_status: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        "UPDATE blocked_events SET status = ? WHERE event_id = ?",
        (new_status, event_id),
    )
    conn.commit()
    conn.close()
    return cur.rowcount > 0


# ─────────────────────────────────────────────
# Mouse Macro Sessions
# ─────────────────────────────────────────────

def save_mouse_macro_session(data: dict) -> str:
    """마우스 매크로 세션을 저장하고 session_id를 반환합니다."""
    conn = sqlite3.connect(DB_PATH)
    now = datetime.now(timezone.utc).isoformat()
    session_id = data.get("session_id", f"MS-{int(datetime.now().timestamp() * 1000)}")

    conn.execute(
        """
        INSERT OR IGNORE INTO mouse_macro_sessions
            (session_id, user_id, probability, confidence, event_count, events_json, detected_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session_id,
            data.get("user_id"),
            data.get("probability", 0.0),
            data.get("confidence", 0.0),
            data.get("event_count", 0),
            json.dumps(data.get("events", [])),
            now,
        ),
    )
    conn.commit()
    conn.close()
    return session_id


def list_mouse_macro_sessions(limit: int = 100) -> list[dict]:
    """최근 마우스 매크로 세션 목록을 반환합니다."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM mouse_macro_sessions ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()

    result = []
    for row in rows:
        try:
            events = json.loads(row["events_json"] or "[]")
        except Exception:
            events = []

        result.append({
            "session_id" : row["session_id"],
            "user_id"    : row["user_id"] or "",
            "probability": row["probability"],
            "confidence" : row["confidence"],
            "event_count": row["event_count"],
            "events"     : events,
            "detected_at": row["detected_at"] or "",
        })
    return result


# ─────────────────────────────────────────────
# 내부 헬퍼
# ─────────────────────────────────────────────

def _reason_to_detection_type(reason_codes: list[str]) -> str:
    """reason_codes를 대시보드 탐지유형 문자열로 변환합니다."""
    for code in reason_codes:
        if "PRECHECK" in code or "WEBDRIVER" in code or "HEADLESS" in code:
            return "정적 통계분석"
        if "BHV" in code or "BEHAVIOR" in code or "RETRY" in code or "CLICK" in code:
            return "동적 행위분석"
        if "NET" in code or "NETWORK" in code or "BURST" in code or "DATACENTER" in code:
            return "LLM 심층분석"
        if "BLACKLIST" in code:
            return "블랙리스트"
    return "동적 행위분석"
