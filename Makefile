pdhcp:
	@mkdir -p build && \
	cd build && \
	cmake -DCMAKE_BUILD_TYPE=Release .. && \
	make && \
	strip pdhcp

server: pdhcp
	./build/pdhcp -b vendor/backend-example.py -n 4

relay: pdhcp
	./build/pdhcp -i eth0 -F 1.2.3.4 -s 4.3.2.1

client: pdhcp
	./build/pdhcp -v -i eth0 | python -mjson.tool

deb:
	@debuild -i -us -uc -b

clean:

distclean:
	@rm -rf build

debclean:
	@debuild clean
	@rm -f ../pdhcp_*
