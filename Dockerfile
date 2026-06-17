# syntax=docker/dockerfile:1
# ---- build stage ----
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=9.0.0
ARG COMMIT=docker
ARG BUILD_DATE=unknown
ENV CGO_ENABLED=0
RUN go build -ldflags "-s -w \
      -X main.version=${VERSION} \
      -X main.commit=${COMMIT} \
      -X main.buildDate=${BUILD_DATE}" \
    -o /out/obscura ./cmd/obscura
# Stage a writable data dir (distroless has no shell to mkdir at runtime).
RUN mkdir -p /out/data

# ---- final stage (distroless, static single binary) ----
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/obscura /app/obscura
COPY --from=build --chown=nonroot:nonroot /out/data /app/data
EXPOSE 8080
ENV OBSCURA_HOST=0.0.0.0 OBSCURA_PORT=8080 OBSCURA_DB_PATH=/app/data/obscura.db
VOLUME ["/app/data"]
USER nonroot:nonroot
ENTRYPOINT ["/app/obscura"]
