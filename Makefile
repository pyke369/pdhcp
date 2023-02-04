#!/bin/sh

# build targets
.PHONY: support
all: pdhcp support
pdhcp: *.go
	@env GOPATH=/tmp/go go get -d && env GOPATH=/tmp/go CGO_ENABLED=0 go build -trimpath -o pdhcp
	@-strip pdhcp 2>/dev/null || true
	@-upx -9 pdhcp 2>/dev/null || true
support:
	@make -C support
clean:
	@make -C support clean
distclean:
	@make -C support distclean
	@rm -f pdhcp *.upx
deb:
	@debuild -e GOROOT -e GOPATH -e PATH -i -us -uc -b
debclean:
	@debuild -- clean
	@rm -f ../pdhcp_*

# run targets
run: pdhcp
	@./pdhcp -i eth0
client: pdhcp
	@./pdhcp -i veth0i
local-backend: pdhcp
	@./pdhcp -i br0 -b support/local-backend.py -w 4
remote-backend: pdhcp
	@./pdhcp -i eth0 -b http://remote.server.com/dhcp
relay: pdhcp
	@./pdhcp -i br0 -r localhost:6767
remote-server: pdhcp
	@./pdhcp -b support/local-backend.py -w 4 -p 6767
