# syntax=docker/dockerfile:1
# Every Go image, from one build of the whole module. Build context is the
# repo root.
#
#   docker build --build-arg SERVICE=organization -f deploy/service.Dockerfile .
#   docker build --target tools -f deploy/service.Dockerfile .    # cmd/*: dbinit, migrate, seed, ...
#
# The build stage compiles every service and command at once and names no
# service, so building several images (the compose stack builds eight
# services and the tools at the same time) compiles the module once: the
# stage is the same for all of them and BuildKit shares it.

FROM golang:1.27-alpine AS build
# The commit this image is built from, for error tracking. Empty locally.
ARG GIT_SHA=
WORKDIR /src
COPY go.mod go.sum ./
# An extra root CA, only for machines whose antivirus or proxy re-signs TLS
# (EXTRA_CA_CERTS in deploy/.env). Used for this step only; never in the image.
# The module and build caches are BuildKit cache mounts, kept between builds.
RUN --mount=type=secret,id=extra_ca,required=false \
  --mount=type=cache,target=/go/pkg/mod \
  if [ -s /run/secrets/extra_ca ]; then export SSL_CERT_FILE=/run/secrets/extra_ca; fi \
  && go mod download
COPY pkg ./pkg
COPY migrations ./migrations
COPY services ./services
COPY cmd ./cmd
RUN --mount=type=cache,target=/go/pkg/mod \
  --mount=type=cache,target=/root/.cache/go-build \
  mkdir -p /out/kms \
  && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/UnityEvolv/b2b-backend-template/pkg/errtrack.release=${GIT_SHA}" -o /out/ ./services/... ./cmd/...

# The platform's command-line tools (cmd/*) in one image.
FROM gcr.io/distroless/static-debian12:nonroot AS tools
COPY --from=build /out/dataowners /out/dbinit /out/migrate /out/seed /out/stubissuer /usr/local/bin/

# One service, the default target.
FROM gcr.io/distroless/static-debian12:nonroot AS service
ARG SERVICE
COPY --from=build /out/${SERVICE} /service
# Where a local master key file lives (KMS_FILE). Owned by the service user,
# so a fresh volume mounted here is writable. Unused when KMS_PROVIDER=gcp.
COPY --from=build --chown=nonroot:nonroot /out/kms /kms
EXPOSE 8080
ENTRYPOINT ["/service"]
