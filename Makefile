#!/bin/sh

# build targets
.PHONY: support
all: pdhcp support
pdhcp: src/*.go
	@export GOPATH=/tmp/go; export CGO_ENABLED=0; cd src && go build -trimpath -o ../pdhcp && cd .. && strip pdhcp
support:
	@make -C support
clean:
	@make -C support clean
distclean:
	@make -C support distclean
	@rm -f pdhcp
deb:
	@debuild -e GOROOT -e GOPATH -e PATH -i -us -uc -b
debclean:
	@debuild clean
	@rm -f ../pdhcp_*

# run targets
client: pdhcp
	@./pdhcp -i veth0i
local-backend: pdhcp
	@./pdhcp -i br0 -b support/local-backend.py -w 4
remote-backend: pdhcp
	@./pdhcp -i br0 -b http://localhost:8000/
relay: pdhcp
	@./pdhcp -i br0 -r localhost:6767
remote-server: pdhcp
	@./pdhcp -b support/local-backend.py -w 4 -p 6767
