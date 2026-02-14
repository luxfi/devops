# Multi-stage build for Lux node with EVM plugin
# Stage 1: Build the Lux node
FROM golang:1.23-alpine AS builder-node
ENV GOTOOLCHAIN=auto
RUN apk add --no-cache git make gcc musl-dev linux-headers
WORKDIR /luxd
COPY node/ .
RUN CGO_ENABLED=0 go build -o build/luxd ./main

# Stage 2: Build the EVM plugin
FROM golang:1.23-alpine AS builder-evm
ENV GOTOOLCHAIN=auto
RUN apk add --no-cache git make gcc musl-dev linux-headers
WORKDIR /build
# Copy both evm and vm directories to maintain the replace directive
COPY vm/ ./vm/
COPY evm/ ./evm/
WORKDIR /build/evm
# The EVM VM ID - this must match what the node expects
ARG EVM_VM_ID=mgj786NP7uDwBCcq6YwThhaN8FLyybkCa4zBWTQbNgmK6k9A6
RUN CGO_ENABLED=0 go build -o build/${EVM_VM_ID} ./plugin

# Stage 3: Runtime image
FROM alpine:3.21 AS execution
RUN apk add --no-cache ca-certificates libc6-compat

# Create user for running the node
RUN addgroup -S luxd && adduser -S luxd -G luxd

WORKDIR /luxd/build
COPY --from=builder-node /luxd/build/luxd ./luxd
COPY --from=builder-evm /build/evm/build/ ./plugins/

# Set permissions
RUN chmod +x luxd && \
    chown -R luxd:luxd /luxd

USER luxd
EXPOSE 9630 9631

ENTRYPOINT ["/luxd/build/luxd"]
