FROM golang:1.24.5 AS builder

RUN mkdir -p /go/src/github.com/firebolt-db/firebolt-auror/cmd/auror
COPY go.* /go/src/github.com/firebolt-db/firebolt-auror/
COPY cmd/auror/*.go /go/src/github.com/firebolt-db/firebolt-auror/cmd/auror/

RUN mkdir -p /go/src/github.com/firebolt-db/firebolt-auror/pkg/webhook/admission
RUN mkdir -p /go/src/github.com/firebolt-db/firebolt-auror/pkg/webhook/cosign
RUN mkdir -p /go/src/github.com/firebolt-db/firebolt-auror/pkg/webhook/cache
RUN mkdir -p /go/src/github.com/firebolt-db/firebolt-auror/pkg/webhook/metrics
RUN mkdir -p /go/src/github.com/firebolt-db/firebolt-auror/pkg/otelutils

COPY pkg/webhook/admission/*.go /go/src/github.com/firebolt-db/firebolt-auror/pkg/webhook/admission/
COPY pkg/webhook/cosign/*.go /go/src/github.com/firebolt-db/firebolt-auror/pkg/webhook/cosign/
COPY pkg/webhook/cache/*.go /go/src/github.com/firebolt-db/firebolt-auror/pkg/webhook/cache/
COPY pkg/webhook/metrics/*.go /go/src/github.com/firebolt-db/firebolt-auror/pkg/webhook/metrics/
COPY pkg/otelutils/*.go /go/src/github.com/firebolt-db/firebolt-auror/pkg/otelutils/

WORKDIR /go/src/github.com/firebolt-db/firebolt-auror

RUN go mod download
RUN go build -o auror cmd/auror/*

FROM gcr.io/distroless/base-debian12:latest

COPY --from=builder /go/src/github.com/firebolt-db/firebolt-auror/auror /bin/auror

USER 65534

ENTRYPOINT ["/bin/auror"]