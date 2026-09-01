FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 go build -o /tls-utls-proxy .

FROM gcr.io/distroless/static-debian12
COPY --from=build /tls-utls-proxy /tls-utls-proxy
EXPOSE 8880
ENTRYPOINT ["/tls-utls-proxy"]
