# syntax=docker/dockerfile:1

# -----------------------------------------------------------------------------
# Stage 1 — build
# -----------------------------------------------------------------------------
# Uses the golang Alpine image so the toolchain version matches go.mod's
# declared version. Kept in a separate stage so the final image never ships
# the compiler, module cache, or source tree.
FROM docker.io/library/golang:1.27-alpine AS builder

WORKDIR /src

# git: required by `go mod download` when a dependency is fetched over VCS.
# ca-certificates: needed at build time for HTTPS module proxies.
# tzdata: copied into the runtime stage so the binary can resolve time zones.
RUN apk add --no-cache git ca-certificates tzdata

# Copy manifests first so this layer is cached and only re-run when
# go.mod/go.sum change — not on every source edit.
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source. Expected to be excluded from the build context
# by .dockerignore (vendor/, .git/, test data, etc.).
COPY . .

# CGO_ENABLED=0   → fully static binary, no glibc/musl dependency at runtime.
# GOOS/GOARCH     → cross-compile targets; adjust for arm64 builds.
# -ldflags "-w -s" → strip DWARF debug info and symbol table to shrink binary.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -o /bin/ord_service ./cmd/api/main.go

# -----------------------------------------------------------------------------
# Stage 2 — runtime
# -----------------------------------------------------------------------------
# Minimal base image: Alpine only provides the CA bundle and tzdata we copy in.
# No shell utilities, no package manager left in the final image; the attack
# surface is just the static binary plus the static assets under /app/web.
FROM docker.io/library/alpine:3.20

WORKDIR /app

# ca-certificates: required for outbound TLS (e.g. Postgres TLS, Qdrant HTTPS).
# tzdata:           required if the service formats timestamps in local time.
RUN apk add --no-cache ca-certificates tzdata

# Copy only runtime artifacts from the builder stage. Source, module cache and
# toolchain stay behind in the builder layer.
COPY --from=builder /bin/ord_service /app/ord_service
COPY --from=builder /src/web          /app/web

# Documentation only: the actual binding is controlled by the app's config.
EXPOSE 8080

# Exec form (JSON array) so the binary is PID 1 and receives signals directly
# (SIGTERM triggers graceful shutdown without a shell wrapper in between).
ENTRYPOINT ["/app/ord_service"]