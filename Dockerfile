FROM ghcr.io/blinklabs-io/go:1.26.3-1 AS build

WORKDIR /code
COPY go.* .
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /code/cdnsd ./cmd/cdnsd
RUN mkdir -p /code/state

FROM cgr.dev/chainguard/glibc-dynamic AS cdnsd
COPY --from=build --chown=nonroot:nonroot /code/cdnsd /usr/bin/cdnsd
COPY --from=build --chown=nonroot:nonroot /code/state /var/lib/cdnsd
WORKDIR /var/lib/cdnsd
ENV STATE_DIR=/var/lib/cdnsd
USER nonroot:nonroot
ENTRYPOINT ["cdnsd"]
