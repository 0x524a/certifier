# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
    -ldflags="-X main.Version=${VERSION}" \
    -o /out/certifier \
    ./cmd/certifier

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/certifier /usr/local/bin/certifier
COPY config.sample.yaml /etc/certifier/config.sample.yaml

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/certifier"]
CMD ["--help"]
