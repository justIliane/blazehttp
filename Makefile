.PHONY: build test test-race bench fuzz lint profile-cpu profile-mem cover vet examples h2spec bench-compare

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOVET=$(GOCMD) vet
GOFUZZ=$(GOTEST) -fuzz
PACKAGE?=./...
BENCH?=.
TIME?=5m
FUZZ_TIME?=5m

# Build
build:
	$(GOBUILD) ./...

# Tests
test:
	$(GOTEST) ./...

test-race:
	$(GOTEST) -race ./...

# Coverage
cover:
	$(GOTEST) -coverprofile=coverage.out -covermode=atomic ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

cover-func:
	$(GOTEST) -coverprofile=coverage.out -covermode=atomic ./...
	$(GOCMD) tool cover -func=coverage.out

# Benchmarks
bench:
	$(GOTEST) -bench=$(BENCH) -benchmem -count=3 ./...

bench-compare:
	$(GOTEST) -bench=$(BENCH) -benchmem -count=5 ./bench/...

# Fuzzing
fuzz:
	$(GOTEST) -fuzz=Fuzz -fuzztime=$(FUZZ_TIME) $(PACKAGE)

# Linting
lint:
	golangci-lint run ./...

vet:
	$(GOVET) ./...

# Profiling
profile-cpu:
	$(GOTEST) -cpuprofile=bench/profile/cpu.prof -bench=$(BENCH) -benchtime=10s ./bench/
	$(GOCMD) tool pprof bench/profile/cpu.prof

profile-mem:
	$(GOTEST) -memprofile=bench/profile/mem.prof -bench=$(BENCH) -benchtime=10s ./bench/
	$(GOCMD) tool pprof bench/profile/mem.prof

# Examples
examples:
	$(GOBUILD) ./examples/...

# H2spec conformance
h2spec:
	h2spec -h localhost -p 8443 -t -k
