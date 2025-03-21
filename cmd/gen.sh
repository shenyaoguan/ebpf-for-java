#!/bin/bash

# Generate the code
go generate ./...

# Build the code
go build -o bin/ ./...
