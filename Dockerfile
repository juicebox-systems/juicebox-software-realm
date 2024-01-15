FROM golang:1.25 as build-env

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o /jb-sw-realm ./cmd/jb-sw-realm

FROM debian:11-slim

RUN apt-get update && apt-get install -y curl supervisor

WORKDIR /otel

RUN curl -LO https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.77.0/otelcol-contrib_0.77.0_linux_amd64.tar.gz \
    && tar -xzvf otelcol-contrib_0.77.0_linux_amd64.tar.gz \
    && mv otelcol-contrib /usr/local/bin/otelcol-contrib \
    && rm -rf /otel

COPY otel-collector-config.yaml /etc/otelcol-contrib/config.yaml

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

COPY --from=build-env /jb-sw-realm /usr/local/bin/jb-sw-realm

ENV PORT 8080

EXPOSE 8080

HEALTHCHECK CMD curl --fail "http://localhost:8080" || exit 1

ENTRYPOINT ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
