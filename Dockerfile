FROM golang:1.21.3

WORKDIR /app

COPY . .

RUN go build -o myapp

CMD ["/app/myapp"]
