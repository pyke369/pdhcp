# This file is part of pdhcp
# Copyright (c) 2014-2015 Pierre-Yves Kerembellec <py.kerembellec@gmail.com>

pdhcp:
	@mkdir -p build && \
	cd build && \
	cmake -DCMAKE_BUILD_TYPE=Release .. && \
	make && \
	strip pdhcp

server: pdhcp
	./build/pdhcp -b vendor/backend-example.py -n 4

client: pdhcp
	./build/pdhcp -v -i eth0 | python -mjson.tool

deb:
	@debuild -i -us -uc -b

clean:

distclean:
	@rm -rf build

debclean:
	@debuild clean
