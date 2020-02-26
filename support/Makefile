#!/bin/sh

# build targets
http-backend: http-backend.go
	@export GOPATH=/tmp/go; export CGO_ENABLED=0; go build -trimpath -o http-backend http-backend.go && strip http-backend
clean:
distclean:
	@rm -f http-backend

# run targets
primary: http-backend
	@./http-backend http-backend.conf
slave: http-backend
	@./http-backend http-backend-slave.conf
