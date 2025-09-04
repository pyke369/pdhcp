#!/bin/sh

PROGNAME=pdhcp
.PHONY: support

# build targets
all: $(PROGNAME) support
$(PROGNAME): *.go
	@env GOPATH=/tmp/go go get && env GOPATH=/tmp/go CGO_ENABLED=0 go build -trimpath -o $(PROGNAME)
	@-strip $(PROGNAME) 2>/dev/null || true
	@#-upx -9 $(PROGNAME) 2>/dev/null || true
support:
	@make -C support
lint:
	@-go vet ./... || true
	@-staticcheck ./... || true
	@-gocritic check -enableAll ./... || true
	@-govulncheck ./... || true
distclean:
	@rm -f $(PROGNAME) *.upx
	@make -C support distclean
deb:
	@debuild -e GOROOT -e GOPATH -e PATH -i -us -uc -b
debclean:
	@debuild -- clean
	@rm -f ../$(PROGNAME)_*

# run targets
client: $(PROGNAME)
	@./$(PROGNAME) -i eth0 -d -P
relay: $(PROGNAME)
	@./$(PROGNAME) -i br0 -r localhost:6767
local: $(PROGNAME)
	@./$(PROGNAME) -i br0 -b support/local-backend.py -w 4
remote: $(PROGNAME)
	@./$(PROGNAME) -i br0 -b http://localhost:6767/dhcp
