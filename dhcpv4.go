package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/pyke369/golang-support/rcache"
)

type V4HWTYPE struct {
	name   string
	length int
}
type V4OPTION struct {
	id       int
	mode     int
	min      int
	max      int
	multiple int
}
type V4MSGTYPE struct {
	name    string
	opcode  byte
	request byte
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
	V4MODE_MSGTYPE   = 12
	V4MODE_OPTION    = 13
	V4MODE_MASK      = 0x7f
	V4MODE_LIST      = 0x80
)

var (
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
		V4MODE_MSGTYPE:   "msgtype",
		V4MODE_OPTION:    "option",
	}
	V4OPCODES = map[byte]string{
		1: "request",
		2: "reply",
	}
	V4HWTYPES = map[byte]*V4HWTYPE{
		1:  &V4HWTYPE{"ethernet", 6},
		6:  &V4HWTYPE{"ieee-802", 0},
		7:  &V4HWTYPE{"arcnet", 0},
		11: &V4HWTYPE{"localtalk", 0},
		12: &V4HWTYPE{"localnet", 0},
		14: &V4HWTYPE{"smds", 0},
		15: &V4HWTYPE{"frame-relay", 0},
		16: &V4HWTYPE{"atm", 0},
		17: &V4HWTYPE{"hdlc", 0},
		18: &V4HWTYPE{"fiber-channel", 0},
		19: &V4HWTYPE{"atm", 0},
		20: &V4HWTYPE{"serial", 0},
	}
	V4RHWTYPES = map[string]byte{}
	V4MSGTYPES = map[byte]*V4MSGTYPE{
		1:  &V4MSGTYPE{"discover", 1, 0},
		2:  &V4MSGTYPE{"offer", 2, 1},
		3:  &V4MSGTYPE{"request", 1, 0},
		4:  &V4MSGTYPE{"decline", 1, 0},
		5:  &V4MSGTYPE{"ack", 2, 3},
		6:  &V4MSGTYPE{"nak", 2, 3},
		7:  &V4MSGTYPE{"release", 1, 0},
		8:  &V4MSGTYPE{"inform", 1, 0},
		9:  &V4MSGTYPE{"forcerenew", 1, 0},
		10: &V4MSGTYPE{"leasequery", 1, 0},
		11: &V4MSGTYPE{"leaseunassigned", 2, 10},
		12: &V4MSGTYPE{"leaseunknown", 2, 10},
		13: &V4MSGTYPE{"leaseactive", 2, 10},
		14: &V4MSGTYPE{"bulkleasequery", 1, 0},
		15: &V4MSGTYPE{"leasequerydone", 2, 14},
	}
	V4RMSGTYPES = map[string]byte{}
	V4OPTIONS   = map[string]*V4OPTION{
		"bootp-opcode":                       &V4OPTION{-14, V4MODE_OPCODE, 1, 1, 0},
		"bootp-hardware-type":                &V4OPTION{-13, V4MODE_HWTYPE, 1, 1, 0},
		"bootp-hardware-length":              &V4OPTION{-12, V4MODE_INTEGER, 1, 1, 0},
		"bootp-relay-hops":                   &V4OPTION{-11, V4MODE_INTEGER, 1, 1, 0},
		"bootp-transaction-id":               &V4OPTION{-10, V4MODE_BINARY, 1, 1, 0},
		"bootp-start-time":                   &V4OPTION{-9, V4MODE_INTEGER, 2, 2, 0},
		"bootp-broadcast":                    &V4OPTION{-8, V4MODE_BOOLEAN, 2, 2, 0},
		"bootp-client-address":               &V4OPTION{-7, V4MODE_INET4, 4, 4, 0},
		"bootp-assigned-address":             &V4OPTION{-6, V4MODE_INET4, 4, 4, 0},
		"bootp-server-address":               &V4OPTION{-5, V4MODE_INET4, 4, 4, 0},
		"bootp-relay-address":                &V4OPTION{-4, V4MODE_INET4, 4, 4, 0},
		"client-hardware-address":            &V4OPTION{-3, V4MODE_SBINARY, 6, 6, 0},
		"bootp-server-name":                  &V4OPTION{-2, V4MODE_STRING, 1, 63, 0},
		"bootp-filename":                     &V4OPTION{-1, V4MODE_STRING, 1, 127, 0},
		"subnet-mask":                        &V4OPTION{1, V4MODE_INET4, 4, 4, 0},
		"time-offset":                        &V4OPTION{2, V4MODE_INTEGER, 4, 4, 0},
		"routers":                            &V4OPTION{3, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"time-servers":                       &V4OPTION{4, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"name-servers":                       &V4OPTION{5, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"domain-name-servers":                &V4OPTION{6, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"log-servers":                        &V4OPTION{7, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"cookie-servers":                     &V4OPTION{8, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"lpr-servers":                        &V4OPTION{9, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"impress-servers":                    &V4OPTION{10, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"resource-location-servers":          &V4OPTION{11, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"hostname":                           &V4OPTION{12, V4MODE_STRING, 1, 0, 0},
		"boot-file-size":                     &V4OPTION{13, V4MODE_INTEGER, 2, 2, 0},
		"merit-dump-file":                    &V4OPTION{14, V4MODE_STRING, 1, 0, 0},
		"domain-name":                        &V4OPTION{15, V4MODE_STRING, 1, 0, 0},
		"swap-server":                        &V4OPTION{16, V4MODE_INET4, 4, 4, 0},
		"root-path":                          &V4OPTION{17, V4MODE_STRING, 1, 0, 0},
		"extensions-path":                    &V4OPTION{18, V4MODE_STRING, 1, 0, 0},
		"ip-forwarding":                      &V4OPTION{19, V4MODE_BOOLEAN, 1, 1, 0},
		"non-local-source-routing":           &V4OPTION{20, V4MODE_BOOLEAN, 1, 1, 0},
		"policy-filters":                     &V4OPTION{21, V4MODE_CIDR4 | V4MODE_LIST, 8, 0, 8},
		"maximum-datagram-reassembly-size":   &V4OPTION{22, V4MODE_INTEGER, 2, 2, 0},
		"ip-default-ttl":                     &V4OPTION{23, V4MODE_INTEGER, 1, 1, 0},
		"path-mtu-aging-timeout":             &V4OPTION{24, V4MODE_INTEGER, 4, 4, 0},
		"path-mtu-plateau-table":             &V4OPTION{25, V4MODE_INTEGER | V4MODE_LIST, 2, 0, 2},
		"interface-mtu":                      &V4OPTION{26, V4MODE_INTEGER, 2, 2, 0},
		"all-subnets-local":                  &V4OPTION{27, V4MODE_BOOLEAN, 1, 1, 0},
		"broadcast-address":                  &V4OPTION{28, V4MODE_INET4, 4, 4, 0},
		"perform-mask-discovery":             &V4OPTION{29, V4MODE_BOOLEAN, 1, 1, 0},
		"mask-supplier":                      &V4OPTION{30, V4MODE_BOOLEAN, 1, 1, 0},
		"perform-router-discovery":           &V4OPTION{31, V4MODE_BOOLEAN, 1, 1, 0},
		"router-solicitation-address":        &V4OPTION{32, V4MODE_INET4, 4, 4, 0},
		"static-routes":                      &V4OPTION{33, V4MODE_INET4PAIR | V4MODE_LIST, 8, 0, 8},
		"trailer-encapsulation":              &V4OPTION{34, V4MODE_BOOLEAN, 1, 1, 0},
		"arp-cache-timeout":                  &V4OPTION{35, V4MODE_INTEGER, 4, 4, 0},
		"ethernet-encapsulation":             &V4OPTION{36, V4MODE_BOOLEAN, 1, 1, 0},
		"tcp-default-ttl":                    &V4OPTION{37, V4MODE_INTEGER, 1, 1, 0},
		"tcp-keepalive-interval":             &V4OPTION{38, V4MODE_INTEGER, 4, 4, 0},
		"tcp-keepalive-garbage":              &V4OPTION{39, V4MODE_BOOLEAN, 1, 1, 0},
		"nis-domain":                         &V4OPTION{40, V4MODE_STRING, 1, 0, 0},
		"nis-servers":                        &V4OPTION{41, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"ntp-servers":                        &V4OPTION{42, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"vendor-specific-information":        &V4OPTION{43, V4MODE_BINARY, 1, 0, 0},
		"netbios-name-servers":               &V4OPTION{44, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"netbios-dgram-distribution-servers": &V4OPTION{45, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"netbios-node-type":                  &V4OPTION{46, V4MODE_INTEGER, 1, 1, 0},
		"netbios-scope":                      &V4OPTION{47, V4MODE_STRING, 1, 0, 0},
		"xwindow-font-servers":               &V4OPTION{48, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"xwindow-display-managers":           &V4OPTION{49, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"requested-ip-address":               &V4OPTION{50, V4MODE_INET4, 4, 4, 0},
		"address-lease-time":                 &V4OPTION{51, V4MODE_INTEGER, 4, 4, 0},
		"option-overload":                    &V4OPTION{52, V4MODE_INTEGER, 1, 1, 0},
		"dhcp-message-type":                  &V4OPTION{53, V4MODE_MSGTYPE, 1, 1, 0},
		"server-identifier":                  &V4OPTION{54, V4MODE_INET4, 4, 4, 0},
		"parameters-request-list":            &V4OPTION{55, V4MODE_OPTION | V4MODE_LIST, 1, 0, 1},
		"message":                            &V4OPTION{56, V4MODE_STRING, 1, 0, 0},
		"max-message-size":                   &V4OPTION{57, V4MODE_INTEGER, 2, 2, 0},
		"renewal-time":                       &V4OPTION{58, V4MODE_INTEGER, 4, 4, 0},
		"rebinding-time":                     &V4OPTION{59, V4MODE_INTEGER, 4, 4, 0},
		"vendor-class-identifier":            &V4OPTION{60, V4MODE_STRING, 1, 0, 0},
		"client-identifier":                  &V4OPTION{61, V4MODE_BINARY, 2, 0, 0},
		"netware-domain":                     &V4OPTION{62, V4MODE_STRING, 1, 0, 0},
		"netware-option":                     &V4OPTION{63, V4MODE_BINARY, 1, 0, 0},
		"nisplus-domain":                     &V4OPTION{64, V4MODE_STRING, 1, 0, 0},
		"nisplus-servers":                    &V4OPTION{65, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"tftp-server-name":                   &V4OPTION{66, V4MODE_STRING, 1, 0, 0},
		"boot-filename":                      &V4OPTION{67, V4MODE_STRING, 1, 0, 0},
		"mobile-ip-home-agents":              &V4OPTION{68, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"smtp-servers":                       &V4OPTION{69, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"pop3-servers":                       &V4OPTION{70, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"nntp-servers":                       &V4OPTION{71, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"www-servers":                        &V4OPTION{72, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"finger-servers":                     &V4OPTION{73, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"irc-servers":                        &V4OPTION{74, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"streettalk-servers":                 &V4OPTION{75, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"streettalk-directory-servers":       &V4OPTION{76, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"user-class":                         &V4OPTION{77, V4MODE_STRING, 1, 0, 0},
		"directory-agent":                    &V4OPTION{78, V4MODE_BINARY, 1, 0, 0},
		"service-scope":                      &V4OPTION{79, V4MODE_BINARY, 1, 0, 0},
		"client-fqdn":                        &V4OPTION{81, V4MODE_BINARY, 1, 0, 0},
		"relay-agent-information":            &V4OPTION{82, V4MODE_BINARY, 1, 0, 0},
		"isns-configuration":                 &V4OPTION{83, V4MODE_BINARY, 1, 0, 0},
		"nds-servers":                        &V4OPTION{85, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"nds-tree-name":                      &V4OPTION{86, V4MODE_STRING, 1, 0, 0},
		"nds-context":                        &V4OPTION{87, V4MODE_STRING, 1, 0, 0},
		"bcmcs-domain":                       &V4OPTION{88, V4MODE_STRING, 1, 0, 0},
		"bcmcs-servers":                      &V4OPTION{89, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"authentication":                     &V4OPTION{90, V4MODE_BINARY, 3, 0, 0},
		"last-transaction-time":              &V4OPTION{91, V4MODE_INTEGER, 4, 4, 0},
		"associated-addresses":               &V4OPTION{92, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"client-system":                      &V4OPTION{93, V4MODE_INTEGER, 2, 2, 0},
		"client-ndi":                         &V4OPTION{94, V4MODE_DINTEGER, 3, 3, 0},
		"client-guid":                        &V4OPTION{97, V4MODE_BINARY, 1, 0, 0},
		"user-authentication":                &V4OPTION{98, V4MODE_STRING, 1, 0, 0},
		"geoconf-civic":                      &V4OPTION{99, V4MODE_BINARY, 1, 0, 0},
		"tz-posix":                           &V4OPTION{100, V4MODE_STRING, 1, 0, 0},
		"tz-database":                        &V4OPTION{101, V4MODE_STRING, 1, 0, 0},
		"auto-configuration":                 &V4OPTION{116, V4MODE_INTEGER, 1, 1, 0},
		"name-service-search":                &V4OPTION{117, V4MODE_INTEGER | V4MODE_LIST, 2, 0, 2},
		"subnet-selection":                   &V4OPTION{118, V4MODE_INET4, 4, 4, 0},
		"domain-search":                      &V4OPTION{119, V4MODE_STRING, 1, 0, 0},
		"sip-server":                         &V4OPTION{120, V4MODE_BINARY, 1, 0, 0},
		"classless-route":                    &V4OPTION{121, V4MODE_BINARY, 1, 0, 0},
		"cablelabs-configuration":            &V4OPTION{122, V4MODE_BINARY, 1, 0, 0},
		"geoconf":                            &V4OPTION{123, V4MODE_BINARY, 1, 0, 0},
		"vi-vendor-class":                    &V4OPTION{124, V4MODE_BINARY, 1, 0, 0},
		"vi-vendor-specific-information":     &V4OPTION{125, V4MODE_BINARY, 1, 0, 0},
		"pana-agents":                        &V4OPTION{136, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"v4-lost":                            &V4OPTION{137, V4MODE_STRING, 1, 0, 0},
		"v4-capwap-access-controller":        &V4OPTION{138, V4MODE_BINARY, 1, 0, 0},
		"v4-address-mos":                     &V4OPTION{139, V4MODE_BINARY, 1, 0, 0},
		"v4-fqdn-mos":                        &V4OPTION{140, V4MODE_BINARY, 1, 0, 0},
		"sip-ua-domain":                      &V4OPTION{141, V4MODE_STRING, 1, 0, 0},
		"v4-address-andsf":                   &V4OPTION{142, V4MODE_BINARY, 1, 0, 0},
		"v4-geoloc":                          &V4OPTION{144, V4MODE_BINARY, 1, 0, 0},
		"forcerenew-nonce-capable":           &V4OPTION{145, V4MODE_BINARY, 1, 0, 0},
		"rdnss-selection":                    &V4OPTION{146, V4MODE_BINARY, 1, 0, 0},
		"tftp-servers":                       &V4OPTION{150, V4MODE_INET4 | V4MODE_LIST, 4, 0, 4},
		"status-code":                        &V4OPTION{151, V4MODE_STRING, 1, 0, 0},
		"base-time":                          &V4OPTION{152, V4MODE_INTEGER, 4, 4, 0},
		"start-time-of-state":                &V4OPTION{153, V4MODE_INTEGER, 4, 4, 0},
		"query-start-time":                   &V4OPTION{154, V4MODE_INTEGER, 4, 4, 0},
		"query-end-time":                     &V4OPTION{155, V4MODE_INTEGER, 4, 4, 0},
		"dhcp-state":                         &V4OPTION{156, V4MODE_INTEGER, 1, 1, 0},
		"data-source":                        &V4OPTION{157, V4MODE_INTEGER, 1, 1, 0},
		"v4-pcp-server":                      &V4OPTION{158, V4MODE_BINARY, 5, 0, 0},
		"pxelinux-magic":                     &V4OPTION{208, V4MODE_BINARY, 4, 4, 0},
		"configuration-file":                 &V4OPTION{209, V4MODE_STRING, 1, 0, 0},
		"path-prefix":                        &V4OPTION{210, V4MODE_STRING, 1, 0, 0},
		"reboot-time":                        &V4OPTION{211, V4MODE_INTEGER, 4, 4, 0},
		"v6-6rd":                             &V4OPTION{212, V4MODE_BINARY, 1, 0, 0},
		"v4-access-domain":                   &V4OPTION{213, V4MODE_STRING, 1, 0, 0},
		"subnet-allocation":                  &V4OPTION{220, V4MODE_BINARY, 1, 0, 0},
		"virtual-subnet-allocation":          &V4OPTION{221, V4MODE_BINARY, 1, 0, 0},
		"private-01":                         &V4OPTION{224, V4MODE_BINARY, 1, 0, 0},
		"private-02":                         &V4OPTION{225, V4MODE_BINARY, 1, 0, 0},
		"private-03":                         &V4OPTION{226, V4MODE_BINARY, 1, 0, 0},
		"private-04":                         &V4OPTION{227, V4MODE_BINARY, 1, 0, 0},
		"private-05":                         &V4OPTION{228, V4MODE_BINARY, 1, 0, 0},
		"private-06":                         &V4OPTION{229, V4MODE_BINARY, 1, 0, 0},
		"private-07":                         &V4OPTION{230, V4MODE_BINARY, 1, 0, 0},
		"private-08":                         &V4OPTION{231, V4MODE_BINARY, 1, 0, 0},
		"private-09":                         &V4OPTION{232, V4MODE_BINARY, 1, 0, 0},
		"private-10":                         &V4OPTION{233, V4MODE_BINARY, 1, 0, 0},
		"private-11":                         &V4OPTION{234, V4MODE_BINARY, 1, 0, 0},
		"private-12":                         &V4OPTION{235, V4MODE_BINARY, 1, 0, 0},
		"private-13":                         &V4OPTION{236, V4MODE_BINARY, 1, 0, 0},
		"private-14":                         &V4OPTION{237, V4MODE_BINARY, 1, 0, 0},
		"private-15":                         &V4OPTION{238, V4MODE_BINARY, 1, 0, 0},
		"private-16":                         &V4OPTION{239, V4MODE_BINARY, 1, 0, 0},
		"private-17":                         &V4OPTION{240, V4MODE_BINARY, 1, 0, 0},
		"private-18":                         &V4OPTION{241, V4MODE_BINARY, 1, 0, 0},
		"private-19":                         &V4OPTION{242, V4MODE_BINARY, 1, 0, 0},
		"private-20":                         &V4OPTION{243, V4MODE_BINARY, 1, 0, 0},
		"private-21":                         &V4OPTION{244, V4MODE_BINARY, 1, 0, 0},
		"private-22":                         &V4OPTION{245, V4MODE_BINARY, 1, 0, 0},
		"private-23":                         &V4OPTION{246, V4MODE_BINARY, 1, 0, 0},
		"private-24":                         &V4OPTION{247, V4MODE_BINARY, 1, 0, 0},
		"private-25":                         &V4OPTION{248, V4MODE_BINARY, 1, 0, 0},
		"private-26":                         &V4OPTION{249, V4MODE_BINARY, 1, 0, 0},
		"private-27":                         &V4OPTION{250, V4MODE_BINARY, 1, 0, 0},
		"private-28":                         &V4OPTION{251, V4MODE_BINARY, 1, 0, 0},
		"private-29":                         &V4OPTION{252, V4MODE_BINARY, 1, 0, 0},
		"private-30":                         &V4OPTION{253, V4MODE_BINARY, 1, 0, 0},
		"private-31":                         &V4OPTION{254, V4MODE_BINARY, 1, 0, 0},
	}
	V4ROPTIONS = map[int]string{}
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
		options := map[string]interface{}{}
		for name, option := range V4OPTIONS {
			options[name] = map[string]interface{}{"id": option.id, "mode": V4MODE_NAMES[option.mode&V4MODE_MASK], "list": option.mode&V4MODE_LIST != 0}
		}
		if pretty {
			if content, err := json.MarshalIndent(options, "", "  "); err == nil {
				fmt.Printf("%s\n", content)
			}
		} else {
			if content, err := json.Marshal(options); err == nil {
				fmt.Printf("%s\n", content)
			}
		}
		return
	}
	fmt.Printf("option                                  type                                    id\n")
	fmt.Printf("--------------------------------------- --------------------------------------- ---\n")
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
			mode = fmt.Sprintf("%dbits integer", 8*option.min)
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
		case V4MODE_OPCODE:
			mode = "BOOTP opcode"
		case V4MODE_HWTYPE:
			mode = "hardware address type"
		case V4MODE_MSGTYPE:
			mode = "DHCP message type"
		case V4MODE_OPTION:
			mode = "DHCP option"
		}
		fmt.Printf("%-40.40s", name)
		if option.mode&V4MODE_LIST != 0 {
			fmt.Printf("%-40.40s", fmt.Sprintf("%s%s list", mode, plural))
		} else {
			fmt.Printf("%-40.40s", mode)
		}
		if option.id > 0 {
			fmt.Printf("%d", option.id)
		} else {
			fmt.Printf("-")
		}
		fmt.Printf("\n")
	}
}

func v4parse(packet []byte) (frame FRAME, err error) {
	frame = FRAME{}
	if len(packet) < 240 {
		return nil, fmt.Errorf(`invalid packet size %d`, len(packet))
	}
	if opcode := V4OPCODES[packet[0]]; opcode == "" {
		return nil, fmt.Errorf(`invalid opcode 0x%02x`, packet[0])
	} else {
		if hwtype := V4HWTYPES[packet[1]]; hwtype == nil || int(packet[2]) > 16 || (hwtype.length != 0 && int(packet[2]) != hwtype.length) {
			return nil, fmt.Errorf(`invalid hardware address type 0x%02x`, packet[1])
		} else {
			frame["bootp-opcode"] = opcode
			frame["bootp-hardware-type"] = hwtype.name
			frame["bootp-hardware-length"] = hwtype.length
		}
	}
	frame["bootp-relay-hops"] = int(packet[3])
	frame["bootp-transaction-id"] = fmt.Sprintf("%08x", binary.BigEndian.Uint32(packet[4:]))
	frame["bootp-start-time"] = int(binary.BigEndian.Uint16(packet[8:]))
	frame["bootp-broadcast"] = packet[10]&0x80 != 0
	if value := binary.BigEndian.Uint32(packet[12:]); value != 0 {
		frame["bootp-client-address"] = fmt.Sprintf("%d.%d.%d.%d", byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
	}
	if value := binary.BigEndian.Uint32(packet[16:]); value != 0 {
		frame["bootp-assigned-address"] = fmt.Sprintf("%d.%d.%d.%d", byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
	}
	if value := binary.BigEndian.Uint32(packet[20:]); value != 0 {
		frame["bootp-server-address"] = fmt.Sprintf("%d.%d.%d.%d", byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
	}
	if value := binary.BigEndian.Uint32(packet[24:]); value != 0 {
		frame["bootp-relay-address"] = fmt.Sprintf("%d.%d.%d.%d", byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
	}
	frame["client-hardware-address"] = strings.ReplaceAll(fmt.Sprintf("% x", packet[28:28+frame["bootp-hardware-length"].(int)]), " ", ":")
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
				name = fmt.Sprintf("%d", packet[offset])
			}
			option := V4OPTIONS[name]
			if option == nil {
				option = &V4OPTION{int(packet[offset]), V4MODE_BINARY, 1, 0, 0}
			}
			size := int(packet[offset+1])
			if size < option.min || (option.max != 0 && size > option.max) && (option.multiple != 0 && size%option.multiple != 0) {
				return nil, fmt.Errorf(`invalid size %d for option "%s"`, size, name)
			}
			if offset+2+size <= len(packet) {
				frame[name] = 0
				if option.mode&V4MODE_LIST != 0 {
					frame[name] = []interface{}{}
				}
				for index := offset + 2; index < offset+2+size; {
					var value interface{}

					switch option.mode & V4MODE_MASK {
					case V4MODE_BINARY:
						value = fmt.Sprintf("%x", packet[index:index+size])
					case V4MODE_SBINARY:
						value = strings.ReplaceAll(fmt.Sprintf("% x", packet[index:index+size]), " ", ":")
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
							return nil, fmt.Errorf(`invalid integer length %d for option "%s"`, option.min, name)
						}
					case V4MODE_DINTEGER:
						dinteger := ""
						for position := index; position < index+size; position++ {
							dinteger += fmt.Sprintf("%d.", packet[position])
						}
						value = strings.Trim(dinteger, ".")
					case V4MODE_BOOLEAN:
						value = packet[index] != 0
					case V4MODE_STRING:
						value = string(packet[offset+2 : offset+2+size])
					case V4MODE_INET4:
						address := binary.BigEndian.Uint32(packet[index:])
						value = fmt.Sprintf("%d.%d.%d.%d", byte(address>>24), byte(address>>16), byte(address>>8), byte(address))
					case V4MODE_INET4PAIR:
						address1 := binary.BigEndian.Uint32(packet[index:])
						address2 := binary.BigEndian.Uint32(packet[index+4:])
						value = fmt.Sprintf("%d.%d.%d.%d:%d.%d.%d.%d",
							byte(address1>>24), byte(address1>>16), byte(address1>>8), byte(address1),
							byte(address2>>24), byte(address2>>16), byte(address2>>8), byte(address2))
					case V4MODE_CIDR4:
						address, bmask := binary.BigEndian.Uint32(packet[index:]), binary.BigEndian.Uint32(packet[index+4:])
						mask := net.IPv4Mask(byte(bmask>>24), byte(bmask>>16), byte(bmask>>8), byte(bmask))
						size, _ := mask.Size()
						value = fmt.Sprintf("%d.%d.%d.%d/%d", byte(address>>24), byte(address>>16), byte(address>>8), byte(address), size)
					case V4MODE_MSGTYPE:
						if msgtype := V4MSGTYPES[packet[index]]; msgtype == nil {
							return nil, fmt.Errorf(`invalid message type 0x%02x`, packet[index])
						} else {
							value = msgtype.name
						}
					case V4MODE_OPTION:
						if value = V4ROPTIONS[int(packet[index])]; value == "" {
							value = fmt.Sprintf("%d", packet[index])
						}
					}
					if value == nil {
						return nil, fmt.Errorf(`invalid value for option "%s"`, name)
					}
					if option.mode&V4MODE_LIST != 0 {
						index += option.multiple
						frame[name] = append(frame[name].([]interface{}), value)
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
	if value, ok := frame["client-hardware-address"].(string); ok {
		key += strings.ReplaceAll(value, ":", "")
	}
	if value, ok := frame["bootp-transaction-id"].(string); ok {
		key += value
	}
	if value, ok := frame["dhcp-message-type"].(string); ok && V4RMSGTYPES[value] != 0 {
		if request := V4MSGTYPES[V4RMSGTYPES[value]].request; request != 0 {
			key += fmt.Sprintf("%02x", request)
		} else {
			key += fmt.Sprintf("%02x", V4RMSGTYPES[value])
		}
	} else {
		key += "01"
	}
	return key
}

func v4build(frame FRAME) (packet []byte, err error) {
	packet = make([]byte, 4<<10)
	dhcp := true
	if value, ok := frame["dhcp-message-type"].(string); !ok || value == "" {
		frame["dhcp-message-type"] = "request"
		dhcp = false
	}
	if value := V4RMSGTYPES[frame["dhcp-message-type"].(string)]; value != 0 {
		packet[0] = V4MSGTYPES[value].opcode
	} else {
		return nil, fmt.Errorf(`invalid message type "%v"`, frame["dhcp-message-type"])
	}
	if value, ok := frame["bootp-hardware-type"].(string); !ok || value == "" {
		frame["bootp-hardware-type"] = "ethernet"
	}
	if value, ok := frame["bootp-hardware-length"].(float64); ok {
		frame["bootp-hardware-length"] = int(value)
	}
	if value := V4RHWTYPES[frame["bootp-hardware-type"].(string)]; value != 0 {
		packet[1] = value
		if length := V4HWTYPES[value].length; length != 0 {
			packet[2] = byte(length)
		} else if value, ok := frame["bootp-hardware-length"].(int); ok && value <= 16 {
			packet[2] = byte(value)
		}
	} else {
		return nil, fmt.Errorf(`invalid hardware address type "%v"`, frame["bootp-hardware-type"])
	}
	if value, ok := frame["bootp-relay-hops"].(float64); ok {
		frame["bootp-relay-hops"] = int(value)
	}
	if value, ok := frame["bootp-relay-hops"].(int); ok {
		packet[3] = byte(value)
	}
	if value, ok := frame["bootp-transaction-id"].(string); ok && len(value) == 8 {
		if id, err := hex.DecodeString(value); err == nil {
			copy(packet[4:], id)
		} else {
			return nil, fmt.Errorf(`invalid transaction id "%v"`, frame)
		}
	}
	if value, ok := frame["bootp-start-time"].(int); ok {
		binary.BigEndian.PutUint16(packet[8:], uint16(value))
	}
	if value, ok := frame["bootp-broadcast"].(bool); ok && value {
		packet[10] |= 0x80
	}
	if value, ok := frame["bootp-client-address"].(string); ok {
		if address := net.ParseIP(value); address != nil && address.To4() != nil {
			copy(packet[12:], address.To4()[:4])
		} else {
			return nil, fmt.Errorf(`invalid client address "%v"`, address)
		}
	}
	if value, ok := frame["bootp-assigned-address"].(string); ok {
		if address := net.ParseIP(value); address != nil && address.To4() != nil {
			copy(packet[16:], address.To4()[:4])
		} else {
			return nil, fmt.Errorf(`invalid assigned address "%v"`, address)
		}
	}
	if value, ok := frame["bootp-server-address"].(string); ok {
		if address := net.ParseIP(value); address != nil && address.To4() != nil {
			copy(packet[20:], address.To4()[:4])
		} else {
			return nil, fmt.Errorf(`invalid server address "%v"`, address)
		}
	}
	if value, ok := frame["bootp-relay-address"].(string); ok {
		if address := net.ParseIP(value); address != nil && address.To4() != nil {
			copy(packet[24:], address.To4()[:4])
		} else {
			return nil, fmt.Errorf(`invalid relay address "%v"`, address)
		}
	}
	if value, ok := frame["client-hardware-address"].(string); ok {
		if !rcache.Get(fmt.Sprintf("^([0-9a-f][0-9a-f]:){%d}[0-9a-f][0-9a-f]$", packet[2]-1)).MatchString(value) {
			return nil, fmt.Errorf(`invalid hardware address "%s"`, value)
		} else {
			hex.Decode(packet[28:], []byte(strings.ReplaceAll(value, ":", "")))
		}
	}
	if value, ok := frame["bootp-server-name"].(string); ok && value != "" {
		copy(packet[44:107], value)
	}
	if value, ok := frame["bootp-filename"].(string); ok && value != "" {
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
			option = &V4OPTION{id, V4MODE_BINARY, 1, 0, 0}
		}
		if option == nil {
			continue
		}
		if _, ok := value.([]interface{}); !ok {
			value = []interface{}{value}
		}
		if option.mode&V4MODE_LIST == 0 && len(value.([]interface{})) > 1 {
			return nil, fmt.Errorf(`option "%s" is not a list of values`, name)
		}

		if offset >= len(packet)-256 {
			return nil, fmt.Errorf(`packet size exceeded`)
		}

		packet[offset] = byte(option.id)
		size := 0
		for _, item := range value.([]interface{}) {
			if _, ok := item.(float64); ok {
				item = int(item.(float64))
			}
			switch option.mode & V4MODE_MASK {
			case V4MODE_BINARY:
				if tvalue, ok := item.(string); ok && tvalue != "" {
					if !rcache.Get(fmt.Sprintf(`^([0-9a-f][0-9a-f]){1,%d}$`, 254-size)).MatchString(tvalue) {
						return nil, fmt.Errorf(`invalid format "%v" for binary option "%s"`, item, name)
					} else {
						hex.Decode(packet[offset+2+size:], []byte(tvalue))
						size += len(tvalue) / 2
					}
				} else {
					return nil, fmt.Errorf(`invalid format "%v" for binary option "%s"`, item, name)
				}
			case V4MODE_SBINARY:
				if tvalue, ok := item.(string); ok && tvalue != "" {
					if !rcache.Get(fmt.Sprintf(`^([0-9a-f][0-9a-f]:){0,%d}[0-9a-f][0-9a-f]$`, 253-size)).MatchString(tvalue) {
						return nil, fmt.Errorf(`invalid format "%v" for separated-binary option "%s"`, item, name)
					} else {
						tvalue = strings.ReplaceAll(tvalue, ":", "")
						hex.Decode(packet[offset+2+size:], []byte(tvalue))
						size += len(tvalue) / 2
					}
				} else {
					return nil, fmt.Errorf(`invalid format "%v" for separated-binary option "%s"`, item, name)
				}
			case V4MODE_INTEGER:
				if tvalue, ok := item.(string); ok {
					if tvalue, err := strconv.Atoi(tvalue); err == nil {
						item = tvalue
					}
				}
				if tvalue, ok := item.(int); ok {
					switch option.min {
					case 1:
						packet[offset+2+size] = byte(tvalue)
					case 2:
						binary.BigEndian.PutUint16(packet[offset+2+size:], uint16(tvalue))
					case 4:
						binary.BigEndian.PutUint32(packet[offset+2+size:], uint32(tvalue))
					case 8:
						binary.BigEndian.PutUint64(packet[offset+2+size:], uint64(tvalue))
					default:
						return nil, fmt.Errorf(`invalid length %d for integer option "%s"`, option.min, name)
					}
					size += option.min
				} else {
					return nil, fmt.Errorf(`invalid format "%v" for integer option "%s"`, item, name)
				}
			case V4MODE_DINTEGER:
				if tvalue, ok := item.(string); ok && tvalue != "" {
					if !rcache.Get(fmt.Sprintf(`^(\d+\.){0,%d}\d+$`, 253-size)).MatchString(tvalue) {
						return nil, fmt.Errorf(`invalid format "%v" for dotted-integer option "%s"`, item, name)
					} else {
						for _, integer := range strings.Split(tvalue, ".") {
							value, _ := strconv.Atoi(integer)
							packet[offset+2+size] = byte(value)
							size++
						}
					}
				} else {
					return nil, fmt.Errorf(`invalid format "%v" for dotted-integer option "%s"`, item, name)
				}
			case V4MODE_BOOLEAN:
				if tvalue, ok := item.(string); ok {
					item = false
					if value = strings.ToLower(strings.TrimSpace(tvalue)); value == "1" || value == "on" || value == "yes" || value == "true" {
						item = true
					}
				}
				if tvalue, ok := item.(bool); ok {
					if tvalue {
						packet[offset+2+size] = 1
					}
					size++
				} else {
					return nil, fmt.Errorf(`invalid format "%v" for boolean option "%s"`, item, name)
				}
			case V4MODE_STRING:
				if tvalue, ok := item.(string); ok && tvalue != "" && len(tvalue) <= 254 {
					copy(packet[offset+2+size:], tvalue)
					size += len(tvalue)
				} else {
					return nil, fmt.Errorf(`invalid format "%v" for string option "%s"`, item, name)
				}
			case V4MODE_INET4:
				if tvalue, ok := item.(string); ok {
					if address := net.ParseIP(tvalue); address == nil || address.To4() == nil {
						return nil, fmt.Errorf(`invalid format "%v" for inet4 option "%s"`, item, name)
					} else {
						copy(packet[offset+2+size:], address.To4()[:4])
						size += 4
					}
				} else {
					return nil, fmt.Errorf(`invalid format "%v" for inet4 option "%s"`, item, name)
				}
			case V4MODE_INET4PAIR:
				if tvalue, ok := item.(string); ok {
					if matcher := rcache.Get(`^((?:\d+\.){3}\d+):((?:\d+\.){3}\d+)$`); !matcher.MatchString(tvalue) {
						return nil, fmt.Errorf(`invalid format "%v" for inet4pair option "%s"`, item, name)
					} else {
						matches := matcher.FindStringSubmatch(tvalue)
						if address1 := net.ParseIP(matches[1]); address1 == nil || address1.To4() == nil {
							return nil, fmt.Errorf(`invalid format "%v" for inet4pair option "%s"`, item, name)
						} else if address2 := net.ParseIP(matches[2]); address2 == nil || address2.To4() == nil {
							return nil, fmt.Errorf(`invalid format "%v" for inet4pair option "%s"`, item, name)
						} else {
							copy(packet[offset+2+size:], address1.To4()[:4])
							copy(packet[offset+2+size+4:], address2.To4()[:4])
							size += 8
						}
					}
				} else {
					return nil, fmt.Errorf(`invalid format "%v" for inet4pair option "%s"`, item, name)
				}
			case V4MODE_CIDR4:
				if tvalue, ok := item.(string); ok {
					if matcher := rcache.Get(`^((?:\d+\.){3}\d+)/(\d+)$`); !matcher.MatchString(tvalue) {
						return nil, fmt.Errorf(`invalid format "%v" for cidr4 option "%s"`, item, name)
					} else {
						matches := matcher.FindStringSubmatch(tvalue)
						if address := net.ParseIP(matches[1]); address == nil || address.To4() == nil {
							return nil, fmt.Errorf(`invalid format "%v" for cidr4 option "%s"`, item, name)
						} else {
							copy(packet[offset+2+size:], address.To4()[:4])
							size += 4
							ones, _ := strconv.Atoi(matches[2])
							mask := net.CIDRMask(ones, 32)
							copy(packet[offset+2+size:], mask[:4])
							size += 4
						}
					}
				} else {
					return nil, fmt.Errorf(`invalid format "%v" for cidr4 option "%s"`, item, name)
				}
			case V4MODE_MSGTYPE:
				if tvalue, ok := item.(string); ok && V4RMSGTYPES[tvalue] != 0 {
					packet[offset+2+size] = V4RMSGTYPES[tvalue]
					size++
				} else {
					return nil, fmt.Errorf(`invalid message type "%v"`, item)
				}
			case V4MODE_OPTION:
				if tvalue, ok := item.(string); ok {
					if option := V4OPTIONS[tvalue]; option != nil {
						packet[offset+2+size] = byte(option.id)
						size++
					} else {
						if id, _ := strconv.Atoi(tvalue); id > 0 && id < 255 {
							packet[offset+2+size] = byte(id)
							size++
						} else {
							return nil, fmt.Errorf(`invalid format "%v" for option "%s"`, item, name)
						}
					}
				} else {
					return nil, fmt.Errorf(`invalid format "%v" for option "%s"`, item, name)
				}
			default:
				return nil, fmt.Errorf(`unknow type %d for option "%s"`, option.mode&V4MODE_MASK, name)
			}
		}
		if (option.min != 0 && size < option.min) || (option.max != 0 && size > option.max) || size > 255 {
			return nil, fmt.Errorf(`out-of-bounds size %d for option "%s"`, size, name)
		}
		packet[offset+1] = byte(size)
		offset += 2 + size
	}
	packet[offset] = 0xff
	offset++
	if offset < 300 {
		offset = 300
	}
	return packet[:offset], nil
}
