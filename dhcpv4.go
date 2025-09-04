package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	j "github.com/pyke369/golang-support/jsonrpc"
	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/ustr"
)

type V4MSGTYPE struct {
	name    string
	opcode  byte
	request byte
}
type V4HWTYPE struct {
	name   string
	length int
}
type V4OPTION struct {
	id   int
	mode int
	min  int
	max  int
	step int
}

const (
	V4MODE_OPCODE    = 1
	V4MODE_HWTYPE    = 2
	V4MODE_BINARY    = 3
	V4MODE_SBINARY   = 4
	V4MODE_INTEGER   = 5
	V4MODE_DINTEGER  = 6
	V4MODE_BOOLEAN   = 7
	V4MODE_STRING    = 8
	V4MODE_INET4     = 9
	V4MODE_INET4PAIR = 10
	V4MODE_CIDR4     = 11
	V4MODE_DOMAIN    = 12
	V4MODE_ROUTE4    = 13
	V4MODE_MSGTYPE   = 14
	V4MODE_OPTION    = 15
	V4MODE_MASK      = 0x7f
	V4MODE_LIST      = 0x80
	FLAG_CLIENTONLY  = 0x01
)

var (
	V4OPCODES = map[byte]string{
		1: "request",
		2: "reply",
	}

	V4RMSGTYPES = map[string]byte{}
	V4MSGTYPES  = map[byte]*V4MSGTYPE{
		1:  &V4MSGTYPE{name: "discover", opcode: 1},
		2:  &V4MSGTYPE{name: "offer", opcode: 2, request: 1},
		3:  &V4MSGTYPE{name: "request", opcode: 1},
		4:  &V4MSGTYPE{name: "decline", opcode: 1},
		5:  &V4MSGTYPE{name: "ack", opcode: 2, request: 3},
		6:  &V4MSGTYPE{name: "nak", opcode: 2, request: 3},
		7:  &V4MSGTYPE{name: "release", opcode: 1},
		8:  &V4MSGTYPE{name: "inform", opcode: 1},
		9:  &V4MSGTYPE{name: "forcerenew", opcode: 1},
		10: &V4MSGTYPE{name: "leasequery", opcode: 1},
		11: &V4MSGTYPE{name: "leaseunassigned", opcode: 2, request: 10},
		12: &V4MSGTYPE{name: "leaseunknown", opcode: 2, request: 10},
		13: &V4MSGTYPE{name: "leaseactive", opcode: 2, request: 10},
		14: &V4MSGTYPE{name: "bulkleasequery", opcode: 1},
		15: &V4MSGTYPE{name: "leasequerydone", opcode: 2, request: 14},
	}

	V4RHWTYPES = map[string]byte{}
	V4HWTYPES  = map[byte]*V4HWTYPE{
		1:  &V4HWTYPE{name: "ethernet", length: 6},
		6:  &V4HWTYPE{name: "ieee-802"},
		7:  &V4HWTYPE{name: "arcnet"},
		11: &V4HWTYPE{name: "localtalk"},
		12: &V4HWTYPE{name: "localnet"},
		14: &V4HWTYPE{name: "smds"},
		15: &V4HWTYPE{name: "frame-relay"},
		16: &V4HWTYPE{name: "atm"},
		17: &V4HWTYPE{name: "hdlc"},
		18: &V4HWTYPE{name: "fiber-channel"},
		19: &V4HWTYPE{name: "atm"},
		20: &V4HWTYPE{name: "serial"},
	}

	V4MODE_NAMES = map[int]string{
		V4MODE_OPCODE:    "opcode",
		V4MODE_HWTYPE:    "hwtype",
		V4MODE_BINARY:    "binary",
		V4MODE_SBINARY:   "sbinary",
		V4MODE_INTEGER:   "integer",
		V4MODE_DINTEGER:  "dinteger",
		V4MODE_BOOLEAN:   "boolean",
		V4MODE_STRING:    "string",
		V4MODE_INET4:     "inet4",
		V4MODE_INET4PAIR: "inet4pair",
		V4MODE_CIDR4:     "cidr4",
		V4MODE_ROUTE4:    "route4",
		V4MODE_DOMAIN:    "domain",
		V4MODE_MSGTYPE:   "msgtype",
		V4MODE_OPTION:    "option",
	}
	V4ROPTIONS = map[int]string{}
	V4OPTIONS  = map[string]*V4OPTION{
		"bootp-opcode":                       &V4OPTION{id: -14, mode: V4MODE_OPCODE, min: 1, max: 1},
		"bootp-hardware-type":                &V4OPTION{id: -13, mode: V4MODE_HWTYPE, min: 1, max: 1},
		"bootp-hardware-length":              &V4OPTION{id: -12, mode: V4MODE_INTEGER, min: 1, max: 1},
		"bootp-relay-hops":                   &V4OPTION{id: -11, mode: V4MODE_INTEGER, min: 1, max: 1},
		"bootp-transaction-id":               &V4OPTION{id: -10, mode: V4MODE_BINARY, min: 1, max: 1},
		"bootp-start-time":                   &V4OPTION{id: -9, mode: V4MODE_INTEGER, min: 2, max: 2},
		"bootp-broadcast":                    &V4OPTION{id: -8, mode: V4MODE_BOOLEAN, min: 2, max: 2},
		"bootp-client-address":               &V4OPTION{id: -7, mode: V4MODE_INET4, min: 4, max: 4},
		"bootp-assigned-address":             &V4OPTION{id: -6, mode: V4MODE_INET4, min: 4, max: 4},
		"bootp-server-address":               &V4OPTION{id: -5, mode: V4MODE_INET4, min: 4, max: 4},
		"bootp-relay-address":                &V4OPTION{id: -4, mode: V4MODE_INET4, min: 4, max: 4},
		"client-hardware-address":            &V4OPTION{id: -3, mode: V4MODE_SBINARY, min: 6, max: 6},
		"bootp-server-name":                  &V4OPTION{id: -2, mode: V4MODE_STRING, min: 1, max: 63},
		"bootp-filename":                     &V4OPTION{id: -1, mode: V4MODE_STRING, min: 1, max: 127},
		"subnet-mask":                        &V4OPTION{id: 1, mode: V4MODE_INET4, min: 4, max: 4},
		"time-offset":                        &V4OPTION{id: 2, mode: V4MODE_INTEGER, min: 4, max: 4},
		"routers":                            &V4OPTION{id: 3, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"time-servers":                       &V4OPTION{id: 4, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"name-servers":                       &V4OPTION{id: 5, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"domain-name-servers":                &V4OPTION{id: 6, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"log-servers":                        &V4OPTION{id: 7, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"cookie-servers":                     &V4OPTION{id: 8, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"lpr-servers":                        &V4OPTION{id: 9, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"impress-servers":                    &V4OPTION{id: 10, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"resource-location-servers":          &V4OPTION{id: 11, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"hostname":                           &V4OPTION{id: 12, mode: V4MODE_STRING, min: 1},
		"boot-file-size":                     &V4OPTION{id: 13, mode: V4MODE_INTEGER, min: 2, max: 2},
		"merit-dump-file":                    &V4OPTION{id: 14, mode: V4MODE_STRING, min: 1},
		"domain-name":                        &V4OPTION{id: 15, mode: V4MODE_STRING, min: 1},
		"swap-server":                        &V4OPTION{id: 16, mode: V4MODE_INET4, min: 4, max: 4},
		"root-path":                          &V4OPTION{id: 17, mode: V4MODE_STRING, min: 1},
		"extensions-path":                    &V4OPTION{id: 18, mode: V4MODE_STRING, min: 1},
		"ip-forwarding":                      &V4OPTION{id: 19, mode: V4MODE_BOOLEAN, min: 1, max: 1},
		"non-local-source-routing":           &V4OPTION{id: 20, mode: V4MODE_BOOLEAN, min: 1, max: 1},
		"policy-filters":                     &V4OPTION{id: 21, mode: V4MODE_CIDR4 | V4MODE_LIST, min: 8, step: 8},
		"maximum-datagram-reassembly-size":   &V4OPTION{id: 22, mode: V4MODE_INTEGER, min: 2, max: 2},
		"ip-default-ttl":                     &V4OPTION{id: 23, mode: V4MODE_INTEGER, min: 1, max: 1},
		"path-mtu-aging-timeout":             &V4OPTION{id: 24, mode: V4MODE_INTEGER, min: 4, max: 4},
		"path-mtu-plateau-table":             &V4OPTION{id: 25, mode: V4MODE_INTEGER | V4MODE_LIST, min: 2, step: 2},
		"interface-mtu":                      &V4OPTION{id: 26, mode: V4MODE_INTEGER, min: 2, max: 2},
		"all-subnets-local":                  &V4OPTION{id: 27, mode: V4MODE_BOOLEAN, min: 1, max: 1},
		"broadcast-address":                  &V4OPTION{id: 28, mode: V4MODE_INET4, min: 4, max: 4},
		"perform-mask-discovery":             &V4OPTION{id: 29, mode: V4MODE_BOOLEAN, min: 1, max: 1},
		"mask-supplier":                      &V4OPTION{id: 30, mode: V4MODE_BOOLEAN, min: 1, max: 1},
		"perform-router-discovery":           &V4OPTION{id: 31, mode: V4MODE_BOOLEAN, min: 1, max: 1},
		"router-solicitation-address":        &V4OPTION{id: 32, mode: V4MODE_INET4, min: 4, max: 4},
		"static-routes":                      &V4OPTION{id: 33, mode: V4MODE_INET4PAIR | V4MODE_LIST, min: 8, step: 8},
		"trailer-encapsulation":              &V4OPTION{id: 34, mode: V4MODE_BOOLEAN, min: 1, max: 1},
		"arp-cache-timeout":                  &V4OPTION{id: 35, mode: V4MODE_INTEGER, min: 4, max: 4},
		"ethernet-encapsulation":             &V4OPTION{id: 36, mode: V4MODE_BOOLEAN, min: 1, max: 1},
		"tcp-default-ttl":                    &V4OPTION{id: 37, mode: V4MODE_INTEGER, min: 1, max: 1},
		"tcp-keepalive-interval":             &V4OPTION{id: 38, mode: V4MODE_INTEGER, min: 4, max: 4},
		"tcp-keepalive-garbage":              &V4OPTION{id: 39, mode: V4MODE_BOOLEAN, min: 1, max: 1},
		"nis-domain":                         &V4OPTION{id: 40, mode: V4MODE_STRING, min: 1},
		"nis-servers":                        &V4OPTION{id: 41, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"ntp-servers":                        &V4OPTION{id: 42, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"vendor-specific-information":        &V4OPTION{id: 43, mode: V4MODE_BINARY, min: 1},
		"netbios-name-servers":               &V4OPTION{id: 44, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"netbios-dgram-distribution-servers": &V4OPTION{id: 45, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"netbios-node-type":                  &V4OPTION{id: 46, mode: V4MODE_INTEGER, min: 1, max: 1},
		"netbios-scope":                      &V4OPTION{id: 47, mode: V4MODE_STRING, min: 1},
		"xwindow-font-servers":               &V4OPTION{id: 48, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"xwindow-display-managers":           &V4OPTION{id: 49, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"requested-ip-address":               &V4OPTION{id: 50, mode: V4MODE_INET4, min: 4, max: 4},
		"address-lease-time":                 &V4OPTION{id: 51, mode: V4MODE_INTEGER, min: 4, max: 4},
		"option-overload":                    &V4OPTION{id: 52, mode: V4MODE_INTEGER, min: 1, max: 1},
		"dhcp-message-type":                  &V4OPTION{id: 53, mode: V4MODE_MSGTYPE, min: 1, max: 1},
		"server-identifier":                  &V4OPTION{id: 54, mode: V4MODE_INET4, min: 4, max: 4},
		"parameters-request-list":            &V4OPTION{id: 55, mode: V4MODE_OPTION | V4MODE_LIST, min: 1, step: 1},
		"message":                            &V4OPTION{id: 56, mode: V4MODE_STRING, min: 1},
		"max-message-size":                   &V4OPTION{id: 57, mode: V4MODE_INTEGER, min: 2, max: 2},
		"renewal-time":                       &V4OPTION{id: 58, mode: V4MODE_INTEGER, min: 4, max: 4},
		"rebinding-time":                     &V4OPTION{id: 59, mode: V4MODE_INTEGER, min: 4, max: 4},
		"vendor-class-identifier":            &V4OPTION{id: 60, mode: V4MODE_STRING, min: 1},
		"client-identifier":                  &V4OPTION{id: 61, mode: V4MODE_BINARY, min: 2},
		"netware-domain":                     &V4OPTION{id: 62, mode: V4MODE_STRING, min: 1},
		"netware-option":                     &V4OPTION{id: 63, mode: V4MODE_BINARY, min: 1},
		"nisplus-domain":                     &V4OPTION{id: 64, mode: V4MODE_STRING, min: 1},
		"nisplus-servers":                    &V4OPTION{id: 65, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"tftp-server-name":                   &V4OPTION{id: 66, mode: V4MODE_STRING, min: 1},
		"boot-filename":                      &V4OPTION{id: 67, mode: V4MODE_STRING, min: 1},
		"mobile-ip-home-agents":              &V4OPTION{id: 68, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"smtp-servers":                       &V4OPTION{id: 69, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"pop3-servers":                       &V4OPTION{id: 70, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"nntp-servers":                       &V4OPTION{id: 71, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"www-servers":                        &V4OPTION{id: 72, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"finger-servers":                     &V4OPTION{id: 73, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"irc-servers":                        &V4OPTION{id: 74, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"streettalk-servers":                 &V4OPTION{id: 75, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"streettalk-directory-servers":       &V4OPTION{id: 76, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"user-class":                         &V4OPTION{id: 77, mode: V4MODE_STRING, min: 1},
		"directory-agent":                    &V4OPTION{id: 78, mode: V4MODE_BINARY, min: 1},
		"service-scope":                      &V4OPTION{id: 79, mode: V4MODE_BINARY, min: 1},
		"client-fqdn":                        &V4OPTION{id: 81, mode: V4MODE_BINARY, min: 1},
		"relay-agent-information":            &V4OPTION{id: 82, mode: V4MODE_BINARY, min: 1},
		"isns-configuration":                 &V4OPTION{id: 83, mode: V4MODE_BINARY, min: 1},
		"nds-servers":                        &V4OPTION{id: 85, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"nds-tree-name":                      &V4OPTION{id: 86, mode: V4MODE_STRING, min: 1},
		"nds-context":                        &V4OPTION{id: 87, mode: V4MODE_STRING, min: 1},
		"bcmcs-domain":                       &V4OPTION{id: 88, mode: V4MODE_STRING, min: 1},
		"bcmcs-servers":                      &V4OPTION{id: 89, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"authentication":                     &V4OPTION{id: 90, mode: V4MODE_BINARY, min: 3},
		"last-transaction-time":              &V4OPTION{id: 91, mode: V4MODE_INTEGER, min: 4, max: 4},
		"associated-addresses":               &V4OPTION{id: 92, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"client-system":                      &V4OPTION{id: 93, mode: V4MODE_INTEGER, min: 2, max: 2},
		"client-ndi":                         &V4OPTION{id: 94, mode: V4MODE_DINTEGER, min: 3, max: 3},
		"client-guid":                        &V4OPTION{id: 97, mode: V4MODE_BINARY, min: 1},
		"user-authentication":                &V4OPTION{id: 98, mode: V4MODE_STRING, min: 1},
		"geoconf-civic":                      &V4OPTION{id: 99, mode: V4MODE_BINARY, min: 1},
		"tz-posix":                           &V4OPTION{id: 100, mode: V4MODE_STRING, min: 1},
		"tz-database":                        &V4OPTION{id: 101, mode: V4MODE_STRING, min: 1},
		"auto-configuration":                 &V4OPTION{id: 116, mode: V4MODE_INTEGER, min: 1, max: 1},
		"name-service-search":                &V4OPTION{id: 117, mode: V4MODE_INTEGER | V4MODE_LIST, min: 2, step: 2},
		"subnet-selection":                   &V4OPTION{id: 118, mode: V4MODE_INET4, min: 4, max: 4},
		"domain-search":                      &V4OPTION{id: 119, mode: V4MODE_DOMAIN | V4MODE_LIST, min: 1},
		"sip-server":                         &V4OPTION{id: 120, mode: V4MODE_BINARY, min: 1},
		"classless-route":                    &V4OPTION{id: 121, mode: V4MODE_ROUTE4 | V4MODE_LIST, min: 5},
		"cablelabs-configuration":            &V4OPTION{id: 122, mode: V4MODE_BINARY, min: 1},
		"geoconf":                            &V4OPTION{id: 123, mode: V4MODE_BINARY, min: 1},
		"vi-vendor-class":                    &V4OPTION{id: 124, mode: V4MODE_BINARY, min: 1},
		"vi-vendor-specific-information":     &V4OPTION{id: 125, mode: V4MODE_BINARY, min: 1},
		"pana-agents":                        &V4OPTION{id: 136, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"v4-lost":                            &V4OPTION{id: 137, mode: V4MODE_STRING, min: 1},
		"v4-capwap-access-controller":        &V4OPTION{id: 138, mode: V4MODE_BINARY, min: 1},
		"v4-address-mos":                     &V4OPTION{id: 139, mode: V4MODE_BINARY, min: 1},
		"v4-fqdn-mos":                        &V4OPTION{id: 140, mode: V4MODE_BINARY, min: 1},
		"sip-ua-domain":                      &V4OPTION{id: 141, mode: V4MODE_STRING, min: 1},
		"v4-address-andsf":                   &V4OPTION{id: 142, mode: V4MODE_BINARY, min: 1},
		"v4-geoloc":                          &V4OPTION{id: 144, mode: V4MODE_BINARY, min: 1},
		"forcerenew-nonce-capable":           &V4OPTION{id: 145, mode: V4MODE_BINARY, min: 1},
		"rdnss-selection":                    &V4OPTION{id: 146, mode: V4MODE_BINARY, min: 1},
		"tftp-servers":                       &V4OPTION{id: 150, mode: V4MODE_INET4 | V4MODE_LIST, min: 4, step: 4},
		"status-code":                        &V4OPTION{id: 151, mode: V4MODE_STRING, min: 1},
		"base-time":                          &V4OPTION{id: 152, mode: V4MODE_INTEGER, min: 4, max: 4},
		"start-time-of-state":                &V4OPTION{id: 153, mode: V4MODE_INTEGER, min: 4, max: 4},
		"query-start-time":                   &V4OPTION{id: 154, mode: V4MODE_INTEGER, min: 4, max: 4},
		"query-end-time":                     &V4OPTION{id: 155, mode: V4MODE_INTEGER, min: 4, max: 4},
		"dhcp-state":                         &V4OPTION{id: 156, mode: V4MODE_INTEGER, min: 1, max: 1},
		"data-source":                        &V4OPTION{id: 157, mode: V4MODE_INTEGER, min: 1, max: 1},
		"v4-pcp-server":                      &V4OPTION{id: 158, mode: V4MODE_BINARY, min: 5},
		"pxelinux-magic":                     &V4OPTION{id: 208, mode: V4MODE_BINARY, min: 4, max: 4},
		"configuration-file":                 &V4OPTION{id: 209, mode: V4MODE_STRING, min: 1},
		"path-prefix":                        &V4OPTION{id: 210, mode: V4MODE_STRING, min: 1},
		"reboot-time":                        &V4OPTION{id: 211, mode: V4MODE_INTEGER, min: 4, max: 4},
		"v6-6rd":                             &V4OPTION{id: 212, mode: V4MODE_BINARY, min: 1},
		"v4-access-domain":                   &V4OPTION{id: 213, mode: V4MODE_STRING, min: 1},
		"subnet-allocation":                  &V4OPTION{id: 220, mode: V4MODE_BINARY, min: 1},
		"virtual-subnet-allocation":          &V4OPTION{id: 221, mode: V4MODE_BINARY, min: 1},
		"private-01":                         &V4OPTION{id: 224, mode: V4MODE_BINARY, min: 1},
		"private-02":                         &V4OPTION{id: 225, mode: V4MODE_BINARY, min: 1},
		"private-03":                         &V4OPTION{id: 226, mode: V4MODE_BINARY, min: 1},
		"private-04":                         &V4OPTION{id: 227, mode: V4MODE_BINARY, min: 1},
		"private-05":                         &V4OPTION{id: 228, mode: V4MODE_BINARY, min: 1},
		"private-06":                         &V4OPTION{id: 229, mode: V4MODE_BINARY, min: 1},
		"private-07":                         &V4OPTION{id: 230, mode: V4MODE_BINARY, min: 1},
		"private-08":                         &V4OPTION{id: 231, mode: V4MODE_BINARY, min: 1},
		"private-09":                         &V4OPTION{id: 232, mode: V4MODE_BINARY, min: 1},
		"private-10":                         &V4OPTION{id: 233, mode: V4MODE_BINARY, min: 1},
		"private-11":                         &V4OPTION{id: 234, mode: V4MODE_BINARY, min: 1},
		"private-12":                         &V4OPTION{id: 235, mode: V4MODE_BINARY, min: 1},
		"private-13":                         &V4OPTION{id: 236, mode: V4MODE_BINARY, min: 1},
		"private-14":                         &V4OPTION{id: 237, mode: V4MODE_BINARY, min: 1},
		"private-15":                         &V4OPTION{id: 238, mode: V4MODE_BINARY, min: 1},
		"private-16":                         &V4OPTION{id: 239, mode: V4MODE_BINARY, min: 1},
		"private-17":                         &V4OPTION{id: 240, mode: V4MODE_BINARY, min: 1},
		"private-18":                         &V4OPTION{id: 241, mode: V4MODE_BINARY, min: 1},
		"private-19":                         &V4OPTION{id: 242, mode: V4MODE_BINARY, min: 1},
		"private-20":                         &V4OPTION{id: 243, mode: V4MODE_BINARY, min: 1},
		"private-21":                         &V4OPTION{id: 244, mode: V4MODE_BINARY, min: 1},
		"private-22":                         &V4OPTION{id: 245, mode: V4MODE_BINARY, min: 1},
		"private-23":                         &V4OPTION{id: 246, mode: V4MODE_BINARY, min: 1},
		"private-24":                         &V4OPTION{id: 247, mode: V4MODE_BINARY, min: 1},
		"private-25":                         &V4OPTION{id: 248, mode: V4MODE_BINARY, min: 1},
		"private-26":                         &V4OPTION{id: 249, mode: V4MODE_BINARY, min: 1},
		"private-27":                         &V4OPTION{id: 250, mode: V4MODE_BINARY, min: 1},
		"private-28":                         &V4OPTION{id: 251, mode: V4MODE_BINARY, min: 1},
		"private-29":                         &V4OPTION{id: 252, mode: V4MODE_BINARY, min: 1},
		"private-30":                         &V4OPTION{id: 253, mode: V4MODE_BINARY, min: 1},
		"private-31":                         &V4OPTION{id: 254, mode: V4MODE_BINARY, min: 1},
	}
)

func init() {
	for id, hwtype := range V4HWTYPES {
		V4RHWTYPES[hwtype.name] = id
	}
	for id, msgtype := range V4MSGTYPES {
		V4RMSGTYPES[msgtype.name] = id
	}
	for name, option := range V4OPTIONS {
		V4ROPTIONS[option.id] = name
	}
}

func v4options(marshal, pretty bool) {
	if marshal {
		options := map[string]map[string]any{}
		for name, option := range V4OPTIONS {
			options[name] = map[string]any{"id": option.id, "mode": V4MODE_NAMES[option.mode&V4MODE_MASK]}
			if option.mode&V4MODE_LIST != 0 {
				options[name]["list"] = true
			}
		}
		content, err := json.Marshal(options)
		if pretty {
			content, err = json.MarshalIndent(options, "", "  ")
		}
		if err == nil {
			os.Stdout.Write(append(content, '\n'))
		}

		return
	}

	os.Stdout.WriteString(
		"option                                  type                                    id\n" +
			"--------------------------------------- --------------------------------------- ---\n",
	)
	ids := []int{}
	for id := range V4ROPTIONS {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		name := V4ROPTIONS[id]
		option := V4OPTIONS[name]
		mode, plural := "", "s"
		switch option.mode & V4MODE_MASK {
		case V4MODE_BINARY:
			mode = "hex-encoded blob"

		case V4MODE_SBINARY:
			mode = "colon-separated hex-encoded blob"

		case V4MODE_INTEGER:
			mode = strconv.Itoa(8*option.min) + "bits integer"

		case V4MODE_DINTEGER:
			mode = "dotted-integer (version)"

		case V4MODE_BOOLEAN:
			mode = "boolean"

		case V4MODE_STRING:
			mode = "string"

		case V4MODE_INET4:
			mode, plural = "IPv4 address", "es"

		case V4MODE_INET4PAIR:
			mode = "IPv4 addresses pair"

		case V4MODE_CIDR4:
			mode = "IPv4 CIDR block"

		case V4MODE_DOMAIN:
			mode = "DNS domain"

		case V4MODE_ROUTE4:
			mode = "IPv4 classless route"

		case V4MODE_OPCODE:
			mode = "BOOTP opcode"

		case V4MODE_HWTYPE:
			mode = "hardware address type"

		case V4MODE_MSGTYPE:
			mode = "DHCP message type"

		case V4MODE_OPTION:
			mode = "DHCP option"
		}
		os.Stdout.WriteString(ustr.String(name, -40))
		if option.mode&V4MODE_LIST != 0 {
			os.Stdout.WriteString(ustr.String(mode+plural+" list", -40))

		} else {
			os.Stdout.WriteString(ustr.String(mode, -40))
		}
		if option.id > 0 {
			os.Stdout.WriteString(strconv.Itoa(option.id) + "\n")

		} else {
			os.Stdout.WriteString("-\n")
		}
	}
}

func v4parse(packet []byte) (frame FRAME, err error) {
	frame = FRAME{}
	if len(packet) < 240 {
		return nil, errors.New("invalid packet size " + strconv.Itoa(len(packet)))
	}
	if opcode := V4OPCODES[packet[0]]; opcode == "" {
		return nil, errors.New("invalid opcode " + strconv.Itoa(int(packet[0])))

	} else {
		if hwtype := V4HWTYPES[packet[1]]; hwtype == nil || int(packet[2]) > 16 || (hwtype.length != 0 && int(packet[2]) != hwtype.length) {
			return nil, errors.New("invalid address type " + strconv.Itoa(int(packet[1])))

		} else {
			frame["bootp-opcode"] = opcode
			frame["bootp-hardware-type"] = hwtype.name
			frame["bootp-hardware-length"] = hwtype.length
		}
	}
	frame["bootp-relay-hops"] = int(packet[3])
	frame["bootp-transaction-id"] = ustr.Hex(packet[4:8])
	frame["bootp-start-time"] = int(binary.BigEndian.Uint16(packet[8:]))
	frame["bootp-broadcast"] = packet[10]&0x80 != 0
	if value := binary.BigEndian.Uint32(packet[12:]); value != 0 {
		frame["bootp-client-address"] = ustr.IPv4(value)
	}
	if value := binary.BigEndian.Uint32(packet[16:]); value != 0 {
		frame["bootp-assigned-address"] = ustr.IPv4(value)
	}
	if value := binary.BigEndian.Uint32(packet[20:]); value != 0 {
		frame["bootp-server-address"] = ustr.IPv4(value)
	}
	if value := binary.BigEndian.Uint32(packet[24:]); value != 0 {
		frame["bootp-relay-address"] = ustr.IPv4(value)
	}
	frame["client-hardware-address"] = ustr.Hex(packet[28:28+int(j.Number(frame["bootp-hardware-length"]))], ':')
	offset := 44
	if packet[offset] != 0 {
		for ; offset < 107; offset++ {
			if packet[offset] == 0 {
				break
			}
		}
		frame["bootp-server-name"] = string(packet[44:offset])
	}
	offset = 108
	if packet[offset] != 0 {
		for ; offset < 235; offset++ {
			if packet[offset] == 0 {
				break
			}
		}
		frame["bootp-filename"] = string(packet[108:offset])
	}
	if value := binary.BigEndian.Uint32(packet[236:]); value != 0x63825363 {
		return frame, nil
	}
	offset = 240

loop:
	for offset < len(packet) {
		switch packet[offset] {
		case 0:
			offset++

		case 0xff:
			break loop

		default:
			name := V4ROPTIONS[int(packet[offset])]
			if name == "" {
				name = strconv.Itoa(int(packet[offset]))
			}
			option := V4OPTIONS[name]
			if option == nil {
				option = &V4OPTION{id: int(packet[offset]), mode: V4MODE_BINARY, min: 1}
			}
			size := int(packet[offset+1])
			if size < option.min || (option.max != 0 && size > option.max) && (option.step != 0 && size%option.step != 0) {
				return nil, errors.New("invalid size " + strconv.Itoa(size) + " for option '" + name + "'")
			}
			if offset+2+size <= len(packet) {
				frame[name] = 0
				if option.mode&V4MODE_LIST != 0 {
					frame[name] = []any{}
				}
				for index := offset + 2; index < offset+2+size; {
					var value any

					switch option.mode & V4MODE_MASK {
					case V4MODE_BINARY:
						value = ustr.Hex(packet[index : index+size])

					case V4MODE_SBINARY:
						value = ustr.Hex(packet[index:index+size], ':')

					case V4MODE_INTEGER:
						switch option.min {
						case 1:
							value = int(packet[index])

						case 2:
							value = int(binary.BigEndian.Uint16(packet[index:]))

						case 4:
							value = int(binary.BigEndian.Uint32(packet[index:]))

						case 8:
							value = int(binary.BigEndian.Uint64(packet[index:]))

						default:
							return nil, errors.New("invalid length " + strconv.Itoa(option.min) + " for option '" + name + "'")
						}

					case V4MODE_DINTEGER:
						dinteger := ""
						for position := index; position < index+size; position++ {
							dinteger += strconv.Itoa(int(packet[position])) + "."
						}
						value = strings.TrimRight(dinteger, ".")

					case V4MODE_BOOLEAN:
						value = packet[index] != 0

					case V4MODE_STRING:
						value = string(packet[offset+2 : offset+2+size])

					case V4MODE_INET4:
						value = ustr.IPv4(binary.BigEndian.Uint32(packet[index:]))

					case V4MODE_INET4PAIR:
						value = ustr.IPv4(binary.BigEndian.Uint32(packet[index:])) + ":" + ustr.IPv4(binary.BigEndian.Uint32(packet[index+4:]))

					case V4MODE_CIDR4:
						mask := net.IPv4Mask(packet[index+4], packet[index+5], packet[index+6], packet[index+7])
						size, _ := mask.Size()
						value = ustr.IPv4(binary.BigEndian.Uint32(packet[index:])) + "/" + strconv.Itoa(size)

					case V4MODE_DOMAIN:
						domain := ""
						for index < offset+2+size {
							if packet[index] == 0 {
								index++
								break
							}
							dsize := int(packet[index])
							if index+dsize > offset+2+size {
								domain = ""
								break
							}
							domain += string(packet[index+1:index+1+dsize]) + "."
							index += 1 + dsize
						}
						if domain != "" {
							value = strings.TrimSuffix(domain, ".")
						}

					case V4MODE_ROUTE4:
						if ones := int(packet[index]); ones <= 32 {
							length, address := ones/8, uint32(0)
							if ones%8 != 0 {
								length++
							}
							for position := 0; position < length; position++ {
								address += uint32(packet[index+1+position]) << ((3 - position) * 8)
							}
							if index+1+length+4 <= offset+2+size {
								value = ustr.IPv4(address) + "/" + strconv.Itoa(ones) + ":" + ustr.IPv4(binary.BigEndian.Uint32(packet[index+1+length:]))
								index += 1 + length + 4
							}
						}

					case V4MODE_MSGTYPE:
						if msgtype := V4MSGTYPES[packet[index]]; msgtype == nil {
							return nil, errors.New("invalid message type " + strconv.Itoa(int(packet[index])))

						} else {
							value = msgtype.name
						}

					case V4MODE_OPTION:
						if value = V4ROPTIONS[int(packet[index])]; value == "" {
							value = strconv.Itoa(int(packet[index]))
						}
					}

					if value == nil {
						return nil, errors.New("invalid value for option '" + name + "'")
					}
					if option.mode&V4MODE_LIST != 0 {
						index += option.step
						frame[name] = append(frame[name].([]any), value)

					} else {
						index += size
						frame[name] = value
					}
				}
			}
			offset += 2 + size
		}
	}
	if frame["dhcp-message-type"] == nil {
		frame["dhcp-message-type"] = "request"
	}

	return frame, nil
}

func v4key(frame FRAME) string {
	key := ""
	if value := j.String(frame["client-hardware-address"]); value != "" {
		key += strings.ReplaceAll(value, ":", "")
	}
	if value := j.String(frame["bootp-transaction-id"]); value != "" {
		key += value
	}
	if value := j.String(frame["dhcp-message-type"]); value != "" && V4RMSGTYPES[value] != 0 {
		if request := V4MSGTYPES[V4RMSGTYPES[value]].request; request != 0 {
			key += strconv.Itoa(int(request))

		} else {
			key += strconv.Itoa(int(V4RMSGTYPES[value]))
		}

	} else {
		key += "1"
	}

	return key
}

func v4build(frame FRAME) (packet []byte, err error) {
	packet = make([]byte, 4<<10)
	dhcp := true
	if value := j.String(frame["dhcp-message-type"]); value == "" {
		frame["dhcp-message-type"], dhcp = "request", false
	}
	if value := V4RMSGTYPES[j.String(frame["dhcp-message-type"])]; value != 0 {
		packet[0] = V4MSGTYPES[value].opcode

	} else {
		return nil, errors.New("invalid message type '" + j.String(frame["dhcp-message-type"]) + "'")
	}
	if value := j.String(frame["bootp-hardware-type"]); value == "" {
		frame["bootp-hardware-type"] = "ethernet"
	}
	if value := V4RHWTYPES[j.String(frame["bootp-hardware-type"])]; value != 0 {
		packet[1] = value
		if length := V4HWTYPES[value].length; length != 0 {
			packet[2] = byte(length)

		} else if value := j.Number(frame["bootp-hardware-length"]); value != 0 && value <= 16 {
			packet[2] = byte(value)
		}

	} else {
		return nil, errors.New("invalid hardware address type '" + j.String(frame["bootp-hardware-type"]) + "'")
	}
	if value := j.Number(frame["bootp-relay-hops"]); value != 0 && value < 32 {
		packet[3] = byte(value)
	}
	if value := j.String(frame["bootp-transaction-id"]); len(value) == 8 {
		if _, err := ustr.Binarize(packet[4:], value); err != nil {
			return nil, errors.New("invalid transaction id '" + value + "`")
		}
	}
	if value := j.Number(frame["bootp-start-time"]); value != 0 {
		binary.BigEndian.PutUint16(packet[8:], uint16(value))
	}
	if j.Boolean(frame["bootp-broadcast"]) {
		packet[10] |= 0x80
	}
	if value := j.String(frame["bootp-client-address"]); value != "" {
		if address := net.ParseIP(value); address != nil && address.To4() != nil {
			copy(packet[12:16], address.To4())

		} else {
			return nil, errors.New("invalid client address '" + value + "'")
		}
	}
	if value := j.String(frame["bootp-assigned-address"]); value != "" {
		if address := net.ParseIP(value); address != nil && address.To4() != nil {
			copy(packet[16:20], address.To4())

		} else {
			return nil, errors.New("invalid assigned address '" + value + "'")
		}
	}
	if value := j.String(frame["bootp-server-address"]); value != "" {
		if address := net.ParseIP(value); address != nil && address.To4() != nil {
			copy(packet[20:24], address.To4())

		} else {
			return nil, errors.New("invalid server address '" + value + "'")
		}
	}
	if value := j.String(frame["bootp-relay-address"]); value != "" {
		if address := net.ParseIP(value); address != nil && address.To4() != nil {
			copy(packet[24:28], address.To4())

		} else {
			return nil, errors.New("invalid relay address '" + value + "'")
		}
	}
	if value := j.String(frame["client-hardware-address"]); value != "" {
		if !rcache.Get(`^([0-9a-f][0-9a-f]:){` + strconv.Itoa(int(packet[2])-1) + `}[0-9a-f][0-9a-f]$`).MatchString(value) {
			return nil, errors.New("invalid hardware address '" + value + "'")

		} else if _, err := ustr.Binarize(packet[28:28+int(packet[2])], strings.ReplaceAll(value, ":", "")); err != nil {
			return nil, errors.New("invalid hardware address '" + value + "'")
		}
	}
	if value := j.String(frame["bootp-server-name"]); value != "" {
		copy(packet[44:107], value)
	}
	if value := j.String(frame["bootp-filename"]); value != "" {
		copy(packet[108:235], value)
	}
	if !dhcp {
		return packet[:300], nil
	}

	binary.BigEndian.PutUint32(packet[236:], 0x63825363)
	offset := 240
	for name, value := range frame {
		var option *V4OPTION = nil

		id := 0
		if id, _ = strconv.Atoi(name); id > 0 && id <= 254 {
			for oname, option := range V4OPTIONS {
				if id == option.id {
					name = oname
					break
				}
			}
		}
		if option = V4OPTIONS[name]; option != nil {
			if option.id < 1 {
				continue
			}

		} else if id != 0 {
			option = &V4OPTION{id: id, mode: V4MODE_BINARY, min: 1}
		}
		if option == nil {
			return nil, errors.New("unknown option '" + name + "'")
		}
		if _, ok := value.([]any); !ok {
			value = []any{value}
		}
		if option.mode&V4MODE_LIST == 0 && len(value.([]any)) > 1 {
			return nil, errors.New("option '" + name + "' is scalar")
		}
		if offset >= len(packet)-256 {
			return nil, errors.New("packet size exceeded")
		}

		packet[offset] = byte(option.id)
		size := 0
		for _, item := range value.([]any) {
			if _, ok := item.(float64); ok {
				item = int(item.(float64))
			}
			switch option.mode & V4MODE_MASK {
			case V4MODE_BINARY:
				if ovalue := j.String(item); ovalue != "" {
					if !rcache.Get(`^([0-9a-f][0-9a-f]){1,` + strconv.Itoa(254-size) + `}$`).MatchString(ovalue) {
						return nil, errors.New("invalid format '" + ovalue + "' for binary option '" + name + "'")

					} else {
						hex.Decode(packet[offset+2+size:], []byte(ovalue))
						size += len(ovalue) / 2
					}

				} else {
					return nil, errors.New("invalid value for binary option '" + name + "'")
				}

			case V4MODE_SBINARY:
				if ovalue := j.String(item); ovalue != "" {
					if !rcache.Get(`^([0-9a-f][0-9a-f]:){0,` + strconv.Itoa(253-size) + `}[0-9a-f][0-9a-f]$`).MatchString(ovalue) {
						return nil, errors.New("invalid format '" + ovalue + "' for separated-binary option '" + name + "'")

					} else {
						ovalue = strings.ReplaceAll(ovalue, ":", "")
						hex.Decode(packet[offset+2+size:], []byte(ovalue))
						size += len(ovalue) / 2
					}

				} else {
					return nil, errors.New("invalid value for separated-binary option '" + name + "'")
				}

			case V4MODE_INTEGER:
				switch option.min {
				case 1:
					packet[offset+2+size] = byte(j.Number(item))

				case 2:
					binary.BigEndian.PutUint16(packet[offset+2+size:], uint16(j.Number(item)))

				case 4:
					binary.BigEndian.PutUint32(packet[offset+2+size:], uint32(j.Number(item)))

				case 8:
					binary.BigEndian.PutUint64(packet[offset+2+size:], uint64(j.Number(item)))

				default:
					return nil, errors.New("invalid length " + strconv.Itoa(option.min) + " for integer option '" + name + "'")

				}
				size += option.min

			case V4MODE_DINTEGER:
				if ovalue := j.String(item); ovalue != "" {
					if !rcache.Get(`^(\d+\.){0,` + strconv.Itoa(253-size) + `}\d+$`).MatchString(ovalue) {
						return nil, errors.New("invalid format '" + ovalue + "' for dotted-integer option '" + name + "'")

					} else {
						for _, integer := range strings.Split(ovalue, ".") {
							value, _ := strconv.Atoi(integer)
							packet[offset+2+size] = byte(value)
							size++
						}
					}

				} else {
					return nil, errors.New("invalid value for dotted-integer option '" + name + "'")
				}

			case V4MODE_BOOLEAN:
				if j.Boolean(item) {
					packet[offset+2+size] = 1
				}
				size++

			case V4MODE_STRING:
				if ovalue := j.String(item); ovalue != "" && len(ovalue) <= 254 {
					copy(packet[offset+2+size:], ovalue)
					size += len(ovalue)

				} else {
					return nil, errors.New("invalid value for string option '" + name + "'")
				}

			case V4MODE_INET4:
				if ovalue := j.String(item); ovalue != "" {
					if address := net.ParseIP(ovalue); address == nil || address.To4() == nil {
						return nil, errors.New("invalid format '" + ovalue + "' for inet4 option '" + name + "'")

					} else {
						copy(packet[offset+2+size:], address.To4()[:4])
						size += 4
					}

				} else {
					return nil, errors.New("invalid value for inet4 option '" + name + "'")
				}

			case V4MODE_INET4PAIR:
				if ovalue := j.String(item); ovalue != "" {
					if captures := rcache.Get(`^((?:\d+\.){3}\d+):((?:\d+\.){3}\d+)$`).FindStringSubmatch(ovalue); captures != nil {
						if address1 := net.ParseIP(captures[1]); address1 == nil || address1.To4() == nil {
							return nil, errors.New("invalid format '" + ovalue + "' for inet4pair option '" + name + "'")

						} else if address2 := net.ParseIP(captures[2]); address2 == nil || address2.To4() == nil {
							return nil, errors.New("invalid format '" + ovalue + "' for inet4pair option '" + name + "'")

						} else {
							copy(packet[offset+2+size:], address1.To4()[:4])
							copy(packet[offset+2+size+4:], address2.To4()[:4])
							size += 8
						}

					} else {
						return nil, errors.New("invalid format '" + ovalue + "' for inet4pair option '" + name + "'")
					}

				} else {
					return nil, errors.New("invalid value for inet4pair option '" + name + "'")
				}

			case V4MODE_CIDR4:
				if ovalue := j.String(item); ovalue != "" {
					if captures := rcache.Get(`^((?:\d+\.){3}\d+)/(\d+)$`).FindStringSubmatch(ovalue); captures != nil {
						if address := net.ParseIP(captures[1]); address == nil || address.To4() == nil {
							return nil, errors.New("invalid format '" + ovalue + "' for cidr4 option '" + name + "'")

						} else {
							copy(packet[offset+2+size:], address.To4()[:4])
							size += 4
							ones, _ := strconv.Atoi(captures[2])
							mask := net.CIDRMask(ones, 32)
							if mask == nil {
								return nil, errors.New("invalid format '" + ovalue + "' for cidr4 option '" + name + "'")
							}
							copy(packet[offset+2+size:], mask[:4])
							size += 4
						}

					} else {
						return nil, errors.New("invalid format '" + ovalue + "' for cidr4 option '" + name + "'")
					}

				} else {
					return nil, errors.New("invalid value for cidr4 option '" + name + "'")
				}

			case V4MODE_DOMAIN:
				if ovalue := j.String(item); ovalue != "" && len(ovalue) < 254 && rcache.Get(`^[a-zA-Z]\.?([a-zA-Z0-9\-]+\.)*$`).MatchString(strings.Trim(ovalue, ".")+".") {
					for _, part := range strings.Split(strings.Trim(ovalue, "."), ".") {
						packet[offset+2+size] = byte(len(part))
						copy(packet[offset+2+size+1:], part)
						size += 1 + len(part)
					}
					packet[offset+2+size] = 0
					size++

				} else {
					return nil, errors.New("invalid value for domain option '" + name + "'")
				}

			case V4MODE_ROUTE4:
				if ovalue := j.String(item); ovalue != "" {
					if matcher := rcache.Get(`^((?:\d+\.){3}\d+)/(\d+):((?:\d+\.){3}\d+)$`); !matcher.MatchString(ovalue) {
						return nil, errors.New("invalid format '" + ovalue + "' for route4 option '" + name + "'")

					} else {
						captures := matcher.FindStringSubmatch(ovalue)
						ones, _ := strconv.Atoi(captures[2])
						if ones < 0 || ones > 32 {
							return nil, errors.New("invalid format '" + ovalue + "' for route4 option '" + name + "'")
						}
						length := ones / 8
						if ones%8 != 0 {
							length++
						}
						packet[offset+2+size] = byte(ones)

						address := net.ParseIP(captures[1])
						if address == nil {
							return nil, errors.New("invalid format '" + ovalue + "' for route4 option '" + name + "'")
						}
						address = address.To4()
						copy(packet[offset+2+size+1:], address[:length])

						address = net.ParseIP(captures[3])
						if address == nil {
							return nil, errors.New("invalid format '" + ovalue + "' for route4 option '" + name + "'")
						}
						address = address.To4()
						copy(packet[offset+2+size+1+length:], address)

						size += 1 + length + 4
					}

				} else {
					return nil, errors.New("invalid value for route4 option '" + name + "'")
				}

			case V4MODE_MSGTYPE:
				if ovalue := j.String(item); ovalue != "" && V4RMSGTYPES[ovalue] != 0 {
					packet[offset+2+size] = V4RMSGTYPES[ovalue]
					size++

				} else {
					return nil, errors.New("invalid message type")
				}

			case V4MODE_OPTION:
				if ovalue := j.String(item); ovalue != "" {
					if option := V4OPTIONS[ovalue]; option != nil {
						packet[offset+2+size] = byte(option.id)
						size++

					} else {
						if id, _ := strconv.Atoi(ovalue); id > 0 && id < 255 {
							packet[offset+2+size] = byte(id)
							size++

						} else {
							return nil, errors.New("invalid format '" + ovalue + "' for option '" + name + "'")
						}
					}

				} else {
					return nil, errors.New("invalid value for option '" + name + "'")
				}

			default:
				return nil, errors.New("unknow type " + strconv.Itoa(option.mode&V4MODE_MASK) + " for option '" + name + "'")
			}
			if size > 255 {
				break
			}
		}
		if (option.min != 0 && size < option.min) || (option.max != 0 && size > option.max) || size > 255 {
			return nil, errors.New("out-of-bounds size " + strconv.Itoa(size) + " for option '" + name + "'")
		}
		packet[offset+1] = byte(size)
		offset += 2 + size
		if offset > len(packet)-255 {
			return nil, errors.New("oversized packet")
		}
	}
	packet[offset] = 0xff
	offset++
	if offset < 300 {
		offset = 300
	}

	return packet[:offset], nil
}
