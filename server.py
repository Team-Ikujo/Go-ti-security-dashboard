# """
# 가드레일 서버에서 BLOCK 이벤트를 수신하는 FastAPI 서버.
# Streamlit 앱(app.py)과 별도 프로세스로 실행됩니다.

# 실행 방법:
#     uvicorn server:app --host 0.0.0.0 --port 8100
# """
# from contextlib import asynccontextmanager
# from typing import Optional

# from fastapi import FastAPI, HTTPException
# from pydantic import BaseModel

# from utils.blocked_db import (
#     init_blocked_db,
#     save_blocked_event,
#     list_blocked_events,
#     get_blocked_stats,
#     update_event_status,
#     save_mouse_macro_session,
#     list_mouse_macro_sessions,
# )


# @asynccontextmanager
# async def lifespan(app: FastAPI):
#     init_blocked_db()
#     yield


# app = FastAPI(title="Go-Ti Security Dashboard API", lifespan=lifespan)


# # ─────────────────────────────────────────────
# # 요청/응답 스키마
# # ─────────────────────────────────────────────

# class BlockedEventRequest(BaseModel):
#     session_id: str
#     user_id: Optional[str] = None
#     ip_address: Optional[str] = None
#     risk_score: Optional[float] = 0.0
#     reason_codes: Optional[list[str]] = []
#     webdriver: Optional[bool] = False
#     headless: Optional[bool] = False
#     devtools_protocol: Optional[bool] = False
#     plugins_count: Optional[int] = 0
#     languages_count: Optional[int] = 0
#     blocked_at: Optional[str] = None   # ISO 8601


# class ActionRequest(BaseModel):
#     action: str   # "Blocked" | "Passed"


# class MouseEventItem(BaseModel):
#     timestamp : int
#     event_type: int
#     screen_x  : float
#     screen_y  : float


# class MouseMacroRequest(BaseModel):
#     session_id : str
#     user_id    : str | None = None
#     probability: float
#     confidence : float
#     event_count: int
#     events     : list[MouseEventItem]


# # ─────────────────────────────────────────────
# # 엔드포인트
# # ─────────────────────────────────────────────

# @app.post("/api/v1/events/blocked", status_code=201)
# def receive_blocked_event(body: BlockedEventRequest):
#     """가드레일 서버에서 BLOCK 판정된 세션 데이터를 수신합니다."""
#     event_id = save_blocked_event(body.model_dump())
#     return {"accepted": True, "event_id": event_id}


# @app.get("/api/v1/detections")
# def get_detections(limit: int = 200):
#     """대시보드 탐지 이벤트 목록을 반환합니다."""
#     return list_blocked_events(limit=limit)


# @app.get("/api/v1/stats/summary")
# def get_stats_summary():
#     """대시보드 상단 통계 카드용 요약 데이터를 반환합니다."""
#     stats = get_blocked_stats()
#     total = stats["total"]
#     return {
#         "total_access": total,
#         "total_access_delta": "+0",
#         "unique_users": total,
#         "unique_users_delta": "+0",
#         "blocked_count": total,
#         "blocked_delta": "+0",
#         "block_rate": 100.0 if total > 0 else 0.0,
#         "block_rate_delta": "+0%",
#     }


# @app.post("/api/v1/events/mouse-macro", status_code=201)
# def receive_mouse_macro(body: MouseMacroRequest):
#     """마우스 매크로 탐지 서버에서 매크로 판정된 세션 데이터를 수신합니다."""
#     session_id = save_mouse_macro_session(body.model_dump())
#     return {"accepted": True, "session_id": session_id}


# @app.get("/api/v1/mouse-macro/sessions")
# def get_mouse_macro_sessions(limit: int = 100):
#     """마우스 매크로 세션 목록을 반환합니다."""
#     return list_mouse_macro_sessions(limit=limit)


# @app.post("/api/v1/interventions/{event_id}/action")
# def update_action(event_id: str, body: ActionRequest):
#     """수동 심사 결과(Block/Pass)를 업데이트합니다."""
#     ok = update_event_status(event_id, body.action)
#     if not ok:
#         raise HTTPException(status_code=404, detail="event not found")
#     return {"success": True, "message": f"status updated to {body.action}"}


# @app.get("/health")
# def health():
#     return {"status": "ok"}
