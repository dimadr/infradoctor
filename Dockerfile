FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 go build -o /infradoctor ./cmd/infradoctor/

FROM scratch
COPY --from=builder /infradoctor /infradoctor
ENTRYPOINT ["/infradoctor"]
CMD ["doctor"]
