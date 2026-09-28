# syntax=docker/dockerfile:1
# The platform's command-line tools (cmd/*) in one image: dbinit, migrate.
# Build context is the repo root.

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
# An extra root CA, only for machines whose antivirus or proxy re-signs TLS
# (EXTRA_CA_CERTS in deploy/.env). Used for this step only; never in the image.
RUN --mount=type=secret,id=extra_ca,required=false \
  if [ -s /run/secrets/extra_ca ]; then export SSL_CERT_FILE=/run/secrets/extra_ca; fi \
  && go mod download
COPY cmd ./cmd
COPY pkg ./pkg
COPY migrations ./migrations
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/...

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ /usr/local/bin/
