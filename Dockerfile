FROM ghcr.io/blinklabs-io/go:1.22.7-1 AS build

WORKDIR /code
COPY . .
RUN make build

FROM cgr.dev/chainguard/glibc-dynamic AS cdnsd
COPY --from=build /code/cdnsd /bin/
ENTRYPOINT ["cdnsd"]
