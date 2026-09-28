# syntax=docker/dockerfile:1
# Any Go service: docker build --build-arg SERVICE=organization -f deploy/service.Dockerfile .
# Build context is the repo root.

FROM golang:1.27-alpine AS build
ARG SERVICE
# The commit this image is built from, for error tracking. Empty locally.
ARG GIT_SHA=
WORKDIR /src
COPY go.mod go.sum ./
# An extra root CA, only for machines whose antivirus or proxy re-signs TLS
# (EXTRA_CA_CERTS in deploy/.env). Used for this step only; never in the image.
# The module and build caches are BuildKit cache mounts, shared by every
# service's build: the second service reuses the first one's downloads and
# compiled packages instead of starting again.
RUN --mount=type=secret,id=extra_ca,required=false \
  --mount=type=cache,target=/go/pkg/mod \
  if [ -s /run/secrets/extra_ca ]; then export SSL_CERT_FILE=/run/secrets/extra_ca; fi \
  && go mod download
COPY pkg ./pkg
COPY migrations ./migrations
COPY services/${SERVICE} ./services/${SERVICE}
RUN --mount=type=cache,target=/go/pkg/mod \
  --mount=type=cache,target=/root/.cache/go-build \
  test -n "${SERVICE}" \
  && mkdir -p /out/kms \
  && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/UnityEvolv/b2b-backend-template/pkg/errtrack.release=${GIT_SHA}" -o /out/service ./services/${SERVICE}

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/service /service
# Where a local master key file lives (KMS_FILE). Owned by the service user,
# so a fresh volume mounted here is writable. Unused when KMS_PROVIDER=gcp.
COPY --from=build --chown=nonroot:nonroot /out/kms /kms
EXPOSE 8080
ENTRYPOINT ["/service"]
