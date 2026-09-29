# cube-logger in a container, for a server that should keep it running. The binary is
# built beforehand, so the server needs Docker and nothing else:
#
#   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o deploy/cube-logger ./cmd/cube-logger
#
# Nothing else goes in the image. cube-logger is one static binary with its UI embedded,
# and everything it writes goes under /data, which compose.yml mounts.
FROM scratch
COPY cube-logger /cube-logger
ENTRYPOINT ["/cube-logger"]
