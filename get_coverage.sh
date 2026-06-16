#!/bin/bash
go test -coverprofile=coverage.out ./internal/core
go tool cover -html=coverage.out -o coverage.html
