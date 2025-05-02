#!/bin/sh

# build targets
http-backend: http-backend.go
	@env GOPATH=/tmp/go go get && env GOPATH=/tmp/go CGO_ENABLED=0 go build -trimpath -o http-backend
	@-strip http-backend 2>/dev/null || true
	@#-upx -9 http-backend 2>/dev/null || true
clean:
distclean:
	@rm -f http-backend *.upx

# run targets
primary: http-backend
	@./http-backend http-backend.conf
slave: http-backend
	@./http-backend http-backend-slave.conf
