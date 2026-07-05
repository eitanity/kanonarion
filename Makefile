.PHONY: build install test lint vet coverage clean fuzz

BINARY := kanonarion
CMD     := ./cmd/kanonarion

# Bounded fuzz budget per target. Override: make fuzz FUZZTIME=2m
FUZZTIME ?= 30s
# Hard per-target wall-clock cap so a single hung input cannot wedge the
# whole sweep. Must exceed FUZZTIME; raise both for longer campaigns.
FUZZTIMEOUT ?= 10m

build:
	go build -o $(BINARY) $(CMD)

install:
	go install $(CMD)

test:
	go test -race -count=1 ./...

coverage:
	go test -race -coverprofile=coverage.out -covermode=atomic -coverpkg=./... ./...
	go tool cover -html=coverage.out -o coverage.html
	go tool cover -func=coverage.out | tail -1

vet:
	go vet ./...

lint: vet
	go tool staticcheck ./...
	go tool govulncheck ./...
	go tool gosec ./...

# Run every FuzzXxx target for FUZZTIME each. Discovers (package, func)
# pairs dynamically so new harnesses are picked up with no Makefile change.
# Committed testdata/fuzz/ crashers are replayed by `make test`; this target
# is for active corpus expansion.
fuzz:
	@pkgs=$$(git grep -l '^func Fuzz' | xargs -n1 dirname | sort -u); \
	failed=""; \
	for pkg in $$pkgs; do \
	  for fn in $$(go test -list '^Fuzz' ./$$pkg/ 2>/dev/null | grep '^Fuzz'); do \
	    echo "==> ./$$pkg $$fn (fuzztime=$(FUZZTIME))"; \
	    if ! go test -run='^$$' -fuzz="^$$fn$$" \
	        -fuzztime=$(FUZZTIME) -test.timeout=$(FUZZTIMEOUT) ./$$pkg/; then \
	      failed="$$failed $$pkg/$$fn"; \
	    fi; \
	  done; \
	done; \
	if [ -n "$$failed" ]; then echo "FUZZ FAILURES:$$failed"; exit 1; fi; \
	echo "all fuzz targets clean"

clean:
	rm -f $(BINARY) coverage.out coverage.html
