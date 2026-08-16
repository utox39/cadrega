# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY pkg/ pkg/

# CGO_ENABLED=0 for a static binary that runs on the distroless base below.
RUN CGO_ENABLED=0 go build -ldflags "-w -s" -o /cadrega ./cmd/cadrega

FROM gcr.io/distroless/static-debian13:nonroot AS final

COPY --from=builder /cadrega /cadrega

EXPOSE 8080

# --address must be 0.0.0.0: `serve`'s default ("localhost") only binds the
# loopback interface, which is unreachable from outside the container. Baked
# into ENTRYPOINT so it can't be dropped by accident; --port is left in CMD
# so `docker run <image> --port 9090` can override just the port.
ENTRYPOINT ["/cadrega", "serve", "--address", "0.0.0.0"]
CMD ["--port", "8080"]
