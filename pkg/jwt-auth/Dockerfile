FROM golang:1.23

WORKDIR /app

# Install dependencies
COPY pkg/jwt-auth/ pkg/jwt-auth/

WORKDIR /app/pkg/jwt-auth

RUN go mod download

# Build the application
RUN CGO_ENABLED=0 go build -o main .

# Run the application
CMD ["./main"]