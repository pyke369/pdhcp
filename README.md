# PDHCP
An efficient programmable BOOTP/DHCP client/server/relay (re-)written in Go.

## Presentation
`pdhcp` is a DHCP toolbox, which can be used to implement client, server or relay roles in a standard
DHCP infrastructure. Contrary to most DHCP packages, `pdhcp` does not directly implement the business
logic of a standard DHCP system, but relies on external helpers (or backends) for that.

The communication protocol between `pdhcp` and these external helpers is based on [JSONL](http://jsonlines.org/):
each DHCP request or response is translated into its JSON object equivalent, serialized, and sent to/received from
the external backends. For instance in client mode (see documentation below), this backend is basically the shell
script starting `pdhcp`, and DHCP responses from servers are simply emitted on the standard output
([gron](https://github.com/tomnomnom/gron) makes JSON grepable):
```
$ pdhcp -i eth0 |gron |gron -u
{
  "address-lease-time": 604800,
  "bootp-assigned-address": "192.168.40.150",
  "bootp-broadcast": true,
  "bootp-filename": "undionly.kpxe",
  "bootp-hardware-length": 6,
  "bootp-hardware-type": "ethernet",
  "bootp-opcode": "reply",
  "bootp-relay-hops": 0,
  "bootp-server-address": "192.168.40.1",
  "bootp-start-time": 0,
  "bootp-transaction-id": "9acb0442",
  "client-hardware-address": "aa:ff:19:93:8d:a6",
  "dhcp-message-type": "offer",
  "domain-name": "domain.com",
  "domain-name-servers": [
     "192.168.40.1"
  ],
  "hostname": "server",
  "routers": [
     "192.168.40.1"
  ],
  "server-identifier": "192.168.40.1",
  "subnet-mask": "255.255.255.0"
}
```

The wrapper script calling `pdhcp` is then responsible for chaining the necessary calls, for instance to perform
a DHCP lease allocation (known as a [DORA](https://www.netmanias.com/en/post/techdocs/5998/dhcp-network-protocol/understanding-the-basic-operations-of-dhcp)
cycle). It may seem like a lot of extra work compared to existing DHCP programs, but it's quite easy to implement
in practice and brings a lot of flexibility in your DHCP infrastructure workflows (especially for large datacenters
servers provisioning scenarii, which is one of the cases `pdhcp` was originally designed for).

`pdhcp` implements [RFC2131](https://tools.ietf.org/html/rfc2131) / [RFC2132](https://tools.ietf.org/html/rfc2132) and most of their subsequent updates.

## Build & Packaging
You may need to install a recent version of the [Golang](https://golang.org/dl/) compiler (>= 1.13) and the GNU [make](https://www.gnu.org/software/make)
utility to build the `pdhcp` binaries,. Once these requirements are fulfilled, clone the `pdhcp` Github repository locally:
```
$ git clone https://github.com/pyke369/pdhcp
```
and type:
```
$ make
```
This will take care of building everything. You may optionally produce a Debian package by typing:
```
$ make deb
```
(the [devscripts](https://packages.debian.org/fr/sid/devscripts) package needs to be installed for this last command)

## Usage
A basic help screen is displayed by using the `-h` command-line parameter:
```
$ pdhcp -h
usage: pdhcp [OPTIONS...]

options are:
  -6	run in IPv6 mode
  -R string
    	add/modify DHCP attributes in the default client request
  -a string
    	use an alternate listen address (default "0.0.0.0")
  -b string
    	specify the backend command path or URL
  -f string
    	provide an alternate logging configuration
  -h	show this help screen
  -i string
    	specify a comma-separated list of interfaces to use
  -j	list all available DHCP options (JSON format)
  -l	list all available DHCP options (human format)
  -p int
    	use an alternate DHCP port (default 67)
  -r string
    	specify the remote DHCP server address in relay mode
  -s string
    	use an alternate local relay address
  -v	show the program version
  -w int
    	change the backend workers count (default 1)
```

The command-line options not specific to a particular running mode are described here:

- `-v`: show the program version and exit:
```
$ pdhcp -v
pdhcp/v2.0.0
```

- `-f`: change the logging configuration string, according to the [ulog](https://github.com/pyke369/golang-support/tree/master/ulog)
syntax:
```
$ pdhcp -f 'file(path=/var/log/pdhcp-%Y%m%d.log) syslog(facility=daemon,name=dhcp-server)'
```

- `-l`: list DHCP options used in the JSONL-based communication protocol, in human-readable format:
```
$ pdhcp -l
option                                  type                                    id
--------------------------------------- --------------------------------------- ---
bootp-opcode                            BOOTP opcode                            -
bootp-hardware-type                     hardware address type                   -
bootp-hardware-length                   8bits integer                           -
bootp-relay-hops                        8bits integer                           -
bootp-transaction-id                    hex-encoded blob                        -
bootp-start-time                        16bits integer                          -
bootp-broadcast                         boolean                                 -
bootp-client-address                    IPv4 address                            -
bootp-assigned-address                  IPv4 address                            -
bootp-server-address                    IPv4 address                            -
bootp-relay-address                     IPv4 address                            -
client-hardware-address                 colon-separated hex-encoded blob        -
bootp-server-name                       string                                  -
bootp-filename                          string                                  -
subnet-mask                             IPv4 address                            1
time-offset                             32bits integer                          2
routers                                 IPv4 addresses list                     3
time-servers                            IPv4 addresses list                     4
...
private-27                              hex-encoded blob                        250
private-28                              hex-encoded blob                        251
private-29                              hex-encoded blob                        252
private-30                              hex-encoded blob                        253
private-31                              hex-encoded blob                        254
```

- `-j`: list DHCP options used in the JSONL-based communication protocol, in machine-parseable format (JSON):
```
$ pdhcp -j |gron |gron -u
{
  "address-lease-time": {
    "id": 51,
    "list": false,
    "mode": "integer"
  },
  "all-subnets-local": {
    "id": 27,
    "list": false,
    "mode": "boolean"
  },
  "arp-cache-timeout": {
    "id": 35,
    "list": false,
    "mode": "integer"
  },
  "associated-addresses": {
    "id": 92,
    "list": true,
    "mode": "inet4"
  },
  "authentication": {
    "id": 90,
    "list": false,
    "mode": "binary"
  },
  "auto-configuration": {
    "id": 116,
    "list": false,
    "mode": "integer"
  },
  ...
}
```

- `-p`: use the specified DHCP server port (default is 67 for DHCPv4, 547 for DHCPv6); the client port is automatically
adjusted against this value (+1=68 for DHCPv4, -1=546 for DHCPv6).
```
$ pdhcp ... -p 6767 ...
```

- `-6`: switch to DHCPv6.
```
$ pdhcp ... -6 ...
```

## Client Mode
The following options can be used in client mode (in addition to the general options above):

- `-i`: specify the network interface name the `pdhcp` client will be using to send DHCP requests; this parameter
is mandatory in client mode:
```
$ pdhcp ... -i eth0 ...
```

- `-R`: add or modify options in the client DHCP request (in JSON format); the client will send the following request
by default:
```
{
  "bootp-transaction-id":    "<random-transaction-id>",
  "bootp-broadcast":         true,
  "dhcp-message-type":       "discover",
  "client-hardware-address": "<interface-MAC-address>",
  "parameters-request-list": [ "hostname", "subnet-mask", "routers", "domain-name", "domain-name-servers", "time-offset", "ntp-servers" ],
  "requested-ip-address":    "<interface-IP-address>",   (if available)
  "hostname":                "<FQDN>"                    (if available)
}
```
For instance, the DHCP message type may be changed in the DHCP request above by using the following syntax:
```
$i pdhcp ... -R '{"dhcp-message-type":"request"}' ...
```

## Server Mode
The following options can be used in server mode (in addition to the general options above):

- `-i`: specify the network interfaces the `pdhcp` server will listen on to receive DHCP requests from clients; any number
of interfaces may be specified; if this parameter is not used at all, the `pdhcp` server will then only listen for requests
from remote DHCP relays:
```
$ pdhcp ... -i eth0,eth1,eth3.456,br0 ...
```

- `-b`: specify the executable path (local CGI mode) or URL (remote HTTP mode) used as backend:
```
$ pdhcp ... -b /usr/share/pdhcp/local-backend.py ...
$ pdhcp ... -b https://user:password@server.domain.com/dhcp ...

```

- `-w`: when the associated backend is a local executable (CGI mode), specify the number of forked processes (a.k.a "workers");
DHCP requests from clients will be load-balanced among all available workers:
```
$ pdhcp ... -w 8 ...
```

## Relay Mode
The following options can be used in relay mode (in addition to the general options above):

- `-i`: specify the network interfaces the `pdhcp` relay will listen on to receive DHCP requests from clients; any number
of interfaces may be specified, and this parameter is mandatory in relay mode. `pdhcp` is capable of listening on non-broadcast
interfaces in relay mode, which may prove useful to receive remote DHCP server responses on tunnel or virtual interfaces:
```
$ pdhcp ... -i eth3,br2,eth0.321 ...
```

- `-r`: specify the remote server to relay DHCP requests to; this parameter is mandatory in relay mode and a custom port may
be specified if needed (67 by default):
```
$ pdhcp ... -r dhcp-server.domain.com:6767 ...
```

- `-s`: the giaddr field (gateway IP address) of the relayed BOOTP packets contains by default the first IP address detected
on the interface receiving the DHCP client requests; using this parameter provide a way to overload this value (note it should
never be used in a regular production setup):
```
$ pdhcp ... -s 192.168.40.10 ...
```

## Support Programs
Some backend examples are provided in the `support` sub-folder, and briefly described here:

- `local-backend.py`: a very basic (but fully functionnal) backend written in Python, designed to run along the `pdhcp`
server process, with the following minimalist command-line:
```
$ pdhcp -b support/local-backend.py -w 4
2020-02-27 16:16:38.312 INFO {"event":"start","mode":"backend","pid":21263,"version":"2.0.0"}
2020-02-27 16:16:38.313 INFO {"event":"listen","listen":"-@0.0.0.0:67"}
2020-02-27 16:16:38.313 INFO {"backend":"support/local-backend.py","event":"worker-start","worker":21269}
2020-02-27 16:16:38.313 INFO {"backend":"support/local-backend.py","event":"worker-start","worker":21270}
2020-02-27 16:16:38.314 INFO {"backend":"support/local-backend.py","event":"worker-start","worker":21271}
2020-02-27 16:16:38.315 INFO {"backend":"support/local-backend.py","event":"worker-start","worker":21272}
```

- `remote-backend.php`: the same backend as above, but written in PHP and supposed to be hosted behind a local or
remote HTTP tiers; an example of invocation from `pdhcp`:
```
$ pdhcp -b https://some-php-server.com/remote-backend.php
2020-02-27 16:17:48.997 INFO {"event":"start","mode":"backend","pid":21333,"version":"2.0.0"}
2020-02-27 16:17:48.998 INFO {"event":"listen","listen":"-@0.0.0.0:67"}
```

- `http-backend`: a full-featured HTTP backend written in Go, with static and dynamic (leases management) support;
the configuration is read from a tree of files, which allows for a clean and potentially complex setup:
```
$ support/http-backend support/http-backend.conf
2020-02-27 16:18:24 INFO {"config":"http-backend.conf","event":"start","pid":21379,"version":"2.0.0"}
2020-02-27 16:18:24 INFO {"event":"listen","listen":"*:8000"}
```

## Limitations
- DHCPv6 is not supported yet.
- *BSD (incl. Darwin/MacOS) platform-specific code (BPF-based) is also not there yet.

## Similar Projects
- [Internet Systems Consortium Kea](https://www.isc.org/kea/)
