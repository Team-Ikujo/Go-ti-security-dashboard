# ─────────────────────────────────────────────
# Stage 1: Build
# ─────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

WORKDIR /build

# 의존성 캐시 레이어 (소스 변경 시 재다운로드 방지)
COPY macro-dashboard-api/go.mod macro-dashboard-api/go.sum ./
RUN go mod download

# 소스 복사 및 빌드
COPY macro-dashboard-api/*.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -trimpath -o macro-dashboard-api .

# ─────────────────────────────────────────────
# Stage 2: Runtime (distroless — ca-certs + tzdata 포함, shell 없음)
# ─────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=builder /build/macro-dashboard-api .

# PVC 마운트 포인트 (SQLite .db 파일 저장 경로)
# K8s manifest에서 /data 를 PVC에 마운트하면 데이터가 영구 보존됩니다.
ENV DATABASE_DIR=/data
ENV PORT=8200

EXPOSE 8200

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/app/macro-dashboard-api", "-healthcheck"]

USER nonroot

ENTRYPOINT ["/app/macro-dashboard-api"]
