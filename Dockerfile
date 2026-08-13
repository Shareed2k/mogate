FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/mogate ./cmd/mogate

FROM alpine:3.22
RUN apk add --no-cache ca-certificates
COPY --from=build /out/mogate /usr/local/bin/mogate
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/mogate"]
