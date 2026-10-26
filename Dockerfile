FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY web/ ./web/
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /subs .

FROM alpine:3
RUN apk add --no-cache ca-certificates && addgroup -g 10001 subs && adduser -D -u 10001 -G subs subs && mkdir /data && chown subs:subs /data
COPY --from=build /subs /usr/local/bin/subs
COPY LICENSE /usr/share/licenses/subs/LICENSE
COPY THIRD_PARTY_NOTICES.md /usr/share/licenses/subs/THIRD_PARTY_NOTICES.md
COPY licenses/ /usr/share/licenses/subs/licenses/
USER subs
ENV SUBS_LISTEN=0.0.0.0:8787 SUBS_DATA_DIR=/data
EXPOSE 8787
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s CMD wget -q -O /dev/null http://127.0.0.1:8787/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/subs"]
