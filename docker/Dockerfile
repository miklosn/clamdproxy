FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download
COPY ./*.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o clamdproxy .

FROM alpine:latest

# Define build arguments with default values
ARG LISTEN_ADDR="0.0.0.0:3315"
ARG BACKEND_ADDR="clamav:3310"
ARG LOG_LEVEL="debug"
ARG METRICS_ADDR="0.0.0.0:2112"

# Create environment variables from the ARGs
ENV LISTEN_ADDR=${LISTEN_ADDR}
ENV BACKEND_ADDR=${BACKEND_ADDR}
ENV LOG_LEVEL=${LOG_LEVEL}
ENV METRICS_ADDR=${METRICS_ADDR}

RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/clamdproxy /app/

# Create a startup script
RUN echo '#!/bin/sh' > /app/start.sh && \
    echo 'exec /app/clamdproxy --listen "$LISTEN_ADDR" --backend "$BACKEND_ADDR" --log-level "$LOG_LEVEL" --metrics "$METRICS_ADDR"' >> /app/start.sh && \
    chmod +x /app/start.sh

EXPOSE 3315 2112
ENTRYPOINT ["/app/start.sh"]