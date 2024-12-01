 
#   * SuSDNS - Proprietary Software
#   * Copyright (c) 2024 Rushikesh Muley. All rights reserved.
#   *
#   * This file is part of SuSDNS. Unauthorized copying, modification, or distribution of this file,
#   * via any medium, is strictly prohibited without prior written permission from the author.
#   *
#   * For inquiries, contact: Rushikesh Muley (rushikeshmuley@outlook.com)
  
# Stage 1: Build the custom CoreDNS binary
FROM golang:1.22 AS builder

# Set the working directory
WORKDIR /go/src/github.com/coredns/coredns

# Clone CoreDNS repository
RUN git clone https://github.com/coredns/coredns.git .

# Copy your local dgadetect plugin
COPY dgadetect plugin/dgadetect

# Add your plugin to plugin.cfg
RUN echo "dgadetect:github.com/coredns/coredns/plugin/dgadetect" >> plugin.cfg

# Update go.mod to include your plugin
RUN go mod edit -replace github.com/coredns/coredns/plugin/dgadetect=./plugin/dgadetect

# Build CoreDNS with the new plugin
RUN go generate
RUN go build -o coredns

# Stage 2: Create the final minimal image using Alpine
FROM alpine:latest

# Install dependencies required by CoreDNS (e.g., libc, etc.)
RUN apk add --no-cache libc6-compat

# Copy the custom built CoreDNS binary from the builder stage
COPY --from=builder /go/src/github.com/coredns/coredns/coredns /coredns

# Copy your Corefile
COPY Corefile /Corefile

# Expose DNS ports
EXPOSE 53 53/udp

# Set the entrypoint to run CoreDNS
ENTRYPOINT ["/coredns"]
