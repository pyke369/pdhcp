# PDHCP
An efficient programmable BOOTP/DHCP client/server/relay (re-)written in Go.

## Presentation
`pdhcp` is a DHCP toolbox, which can be used to implement client, server or relay roles in a standard DHCP infrastructure.
Contrary to most DHCP packages, `pdhcp` does not directly implement the business logic of a standard DHCP system, but relies
on external helpers (or backends) for that.

The communication protocol between `pdhcp` and these external helpers is based on [JSONL](http://jsonlines.org/): each DHCP
request or response is translated into its JSON object equivalent, serialized, and sent to/received from the external backends.
For instance in client mode (see documentation below), this backend is basically the shell script starting `pdhcp`, and responses
from servers are simply emitted on the standard output ([gron](https://github.com/tomnomnom/gron) makes JSON grepable):
```
$ pdhcp -i eth0 -d -P
> request {
>   "bootp-broadcast": true,
>   "bootp-hardware-type": "ethernet",
>   "bootp-transaction-id": "ec91e633",
>   "client-hardware-address": "00:0c:29:90:a4:e8",
>   "dhcp-message-type": "discover",
>   "parameters-request-list": [
>     "hostname",
>     "subnet-mask",
>     "routers",
>     "domain-name",
>     "domain-name-servers",
>     "domain-search",
>     "classless-route",
>     "time-offset",
>     "ntp-servers"
>   ],
> }

< response {
<   "address-lease-time": 1800,
<   "bootp-assigned-address": "192.168.29.150",
<   "bootp-broadcast": true,
<   "bootp-hardware-length": 6,
<   "bootp-hardware-type": "ethernet",
<   "bootp-opcode": "reply",
<   "bootp-relay-hops": 0,
<   "bootp-server-address": "192.168.29.254",
<   "bootp-start-time": 0,
<   "bootp-transaction-id": "ec91e633",
<   "client-hardware-address": "00:0c:29:90:a4:e8",
<   "dhcp-message-type": "offer",
<   "domain-name": "localdomain",
<   "domain-name-servers": [
<     "192.168.29.2"
<   ],
<   "routers": [
<     "192.168.29.2"
<   ],
<   "server-identifier": "192.168.29.254",
<   "subnet-mask": "255.255.255.0"
< }
```
The wrapper script calling `pdhcp` is then responsible for chaining the necessary calls, for instance to perform a DHCP lease
allocation (a.k.a. [DORA](https://www.netmanias.com/en/post/techdocs/5998/dhcp-network-protocol/understanding-the-basic-operations-of-dhcp)
cycle).  It may seem like a lot of extra work compared to existing DHCP programs, but it's quite easy to implement in practice
and brings a lot of flexibility in your DHCP infrastructure workflows (especially for large datacenters servers provisioning
scenarii, which is one of the cases `pdhcp` was originally designed for).

`pdhcp` implements [RFC2131](https://tools.ietf.org/html/rfc2131) / [RFC2132](https://tools.ietf.org/html/rfc2132) and most of
their subsequent updates.

## Build & Packaging
The simplest way to get `pdhcp` on your system is to install a recent version of the [Golang](https://golang.org/dl/) toolchain
and then issue the following command:
```
$ env GOBIN=$PWD go install github.com/pyke369/pdhcp@latest
```
This will take care of downloading the source code and building the binary. You may optionally produce a Debian package by cloning
the repository and issuing the following command:
```
$ make deb
```
(the [devscripts](https://packages.debian.org/bullseye/devscripts) package needs to be installed for this last command to work)

## Usage
A basic help screen is displayed by using the `-h` command-line parameter:
```
$ pdhcp -h
usage: pdhcp [<option>...]

options are:
  -6    run in IPv6 mode
  -C string
        use CA certificate (remote backend)
  -H value
        add HTTP header (remote backend / repeatable)
  -I    allow insecure TLS connections (remote backend)
  -P    pretty-print JSON
  -R string
        overload default options (client mode)
  -a string
        use alternate address (server/relay modes) (default "*")
  -b string
        set backend command/url
  -c string
        use client certificate (remote backend)
  -d    dump request (client mode)
  -f string
        use alternate logging format
  -i string
        use specified interface(s)
  -j    list available DHCP options (JSON format)
  -l    list available DHCP options (human format)
  -p int
        use alternate port (server/relay modes) (default 67)
  -r string
        set remote DHCP server address (relay mode)
  -s string
        use specified alternate relay local address (relay mode)
  -t int
        set backend timeout (default 7)
  -v    show program version and exit
  -w int
        set workers count (local backend) (default 1)
```

The command-line options unspecific to a particular run mode are described below.

- `-v`: show program version and exit.
```
$ pdhcp -v
pdhcp v2.3.0
```

- `-f`: use alternate logging format (ccording to the [ulog](https://github.com/pyke369/golang-support/tree/master/ulog) syntax).
```
$ pdhcp -f 'file(path=/var/log/pdhcp-%Y%m%d.log) syslog(facility=daemon,name=dhcp-server)'
```

- `-l`: list available DHCP options (in human-readable form).
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
private-29                              hex-encoded blob                        252
private-30                              hex-encoded blob                        253
private-31                              hex-encoded blob                        254
```

- `-j`:  list available DHCP options (in machine-parseable JSON form).
```
$ pdhcp -j -P
{
  "address-lease-time": {
    "id": 51,
    "mode": "integer"
  },
  "all-subnets-local": {
    "id": 27,
    "mode": "boolean"
  },
  "arp-cache-timeout": {
    "id": 35,
    "mode": "integer"
  },
  "associated-addresses": {
    "id": 92,
    "list": true,
    "mode": "inet4"
  },
  "authentication": {
    "id": 90,
    "mode": "binary"
  },
  "auto-configuration": {
    "id": 116,
    "mode": "integer"
  },
  ...
}
```

- `-P`: pretty-print JSON (see above a combination with the `-j` option).

- `-p`: use alternate DHCP port (default is 67 for DHCPv4, 547 for DHCPv6); the client port is automatically adjusted against
this value (+1 = 68 for DHCPv4, -1 = 546 for DHCPv6).
```
$ pdhcp -p 6767
```

- `-6`: switch to DHCPv6.
```
$ pdhcp -6
```

## Client Mode
The following options can be used in client mode (in addition to the general options above):

- `-i`: use specified interface to send DHCP requests over (mandatory in client mode).
```
$ pdhcp -i eth0
```

- `-R`: overload options in the following client default DHCP request (in JSON format):
```
{
  "bootp-transaction-id":    "<random>",
  "bootp-broadcast":         true,
  "dhcp-message-type":       "discover",
  "client-hardware-address": "<mac address>",
  "parameters-request-list": [ "hostname", "subnet-mask", "routers", "domain-name",
                               "domain-name-servers", "domain-search", "classless-route",
                               "time-offset", "ntp-servers" ],
  "requested-ip-address":    "<ip address>",  # optional
  "hostname":                "<hostname>"     # optional
}
```
The DHCP message type would be changed in the DHCP request above by using the following syntax:
```
$ pdhcp -R '{"dhcp-message-type": "request"}'
```

- `-d`: dump DHCP request in JSON form (in addition to DHCP response).

## Server Mode
The following options can be used in server and relay modes (in addition to the general options above).

- `-i`: set the interfaces `pdhcp` will listen to for receiving DHCP requests from clients (any number of interfaces can be
specified, and `pdhcp` will only responed to DHCP relays if none is provided).
```
$ pdhcp -i eth0,eth3.456,br0
```

- `-a`: use alternate listening address (all by default).
```
$ pdhcp -a 192.168.40.1
```

- `-b`: set the command (local mode) or URL (remote mode) used as backend:
```
$ pdhcp -b /usr/share/pdhcp/local-backend.py
$ pdhcp -b https://user:password@server.domain.com/dhcp
```

- `-w`: set the number of workers" in local backend mode (DHCP requests will be load-balanced among all available workers).
```
$ pdhcp -w 8
```

- `-t`: set remote backend timeout.
```
$ pdhcp -t 15
```

- `-H`: add HTTP header to remote backend requests (the option is repeatable to add several).
```
$ pdhcp -H 'Token: xyz' -H 'User-Agent: myagent'
```

- `-I`: ignore TLS server certificate errors.
```
$ pdhcp -I
```

- `-C`: use specific CA certificate (to valivate remote server certificate).
```
$ pdhcp -C cacert.pem
```

- `-c`: present client certificate to server (for mTLS deployments).
```
$ pdhcp -c cert.pem,key.pem
```

## Relay Mode
The following options can be used in relay mode (in addition to the general and server options above).

- `-i`: set the interfaces `pdhcp` will listen to for receiving DHCP requests from clients (any number of interfaces can be
specified, mandatory in relay mode). `pdhcp` can listen on non-broadcast interfaces in relay mode, which may prove useful to
receive responses on tunnel or virtual interfaces.
```
$ pdhcp -i eth3,br2,tun0
```

- `-r`: set the remote server to relay DHCP requests to (mandatory in relay mode).
```
$ pdhcp -r dhcp.domain.com:6767
```

- `-s`: use alternate relay local address (by default the first ip address detected on the associated interface).
```
$ pdhcp -s 192.168.40.10
```

## Support
Some backend examples are provided in the `support` folder, and briefly described here:

- `local-backend.py`: a very basic (but fully functionnal) backend written in Python, designed to run as a `pdhcp` co-process.
```
$ pdhcp -b support/local-backend.py -w 4
2025-09-09 15:41:54.249 INFO {"event":"start","mode":"server","version":"2.3.0","pid":191199}
2025-09-09 15:41:54.250 INFO {"event":"bind","bind":"*:67","mode":"server"}
2025-09-09 15:41:54.251 INFO {"event":"start","local":"support/local-backend.py","worker":191209}
2025-09-09 15:41:54.251 INFO {"event":"start","local":"support/local-backend.py","worker":191206}
2025-09-09 15:41:54.252 INFO {"event":"start","local":"support/local-backend.py","worker":191208}
2025-09-09 15:41:54.253 INFO {"event":"start","local":"support/local-backend.py","worker":191207}
```

- `http-backend`: a full-featured HTTP backend written in Go, with static and dynamic (leases management) support (the configuration
is read from a filetree, allowing for a cleaner and potentially complex setup).
```
$ support/http-backend support/http-backend.conf
2025-09-09 15:41:56.732 INFO {"event":start,"config":"support/http-backend.conf","version":"2.0.0","pid":21379}
2025-09-09 15:41:56.732 INFO {"event":"listen","listen":"*:8000"}
```

## Limitations
- DHCPv6 is not supported (yet).
- \*BSD (incl. Darwin/MacOS) platform-specific code (BPF-based) is not there (yet).

## Similar Projects
- [Internet Systems Consortium Kea](https://www.isc.org/kea/)
