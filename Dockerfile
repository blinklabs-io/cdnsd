FROM ghcr.io/blinklabs-io/go:1.25.5-1 AS build

WORKDIR /code
COPY go.* .
RUN go mod download
COPY . .
RUN make build

FROM cgr.dev/chainguard/glibc-dynamic AS cdnsd
COPY --from=build /code/cdnsd /bin/
ENTRYPOINT ["cdnsd"]
