// This file is part of pdhcp
// Copyright (c) 2015 Pierre-Yves Kerembellec <py.kerembellec@gmail.com>

// includes
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include <util.h>
#include <dhcp.h>

// defines
#define  DHCP_FRAME_MAGIC            (0x63538263)

#define  DHCP_FRAME_RELAYHOPS        (0x0101)
#define  DHCP_FRAME_TRANSACTIONID    (0x0102)
#define  DHCP_FRAME_STARTTIME        (0x0103)
#define  DHCP_FRAME_CLIENTADDRESS    (0x0104)
#define  DHCP_FRAME_ASSIGNEDADDRESS  (0x0105)
#define  DHCP_FRAME_SERVERADDRESS    (0x0106)
#define  DHCP_FRAME_RELAYADDRESS     (0x0107)
#define  DHCP_FRAME_CLIENTHWADDRESS  (0x0108)
#define  DHCP_FRAME_SERVERNAME       (0x0109)
#define  DHCP_FRAME_FILENAME         (0x010a)

#define  DHCP_OPTION_NONE            (0x00)
#define  DHCP_OPTION_OPAQUE          (0x01)
#define  DHCP_OPTION_INTEGER         (0x02)
#define  DHCP_OPTION_BOOLEAN         (0x03)
#define  DHCP_OPTION_STRING          (0x04)
#define  DHCP_OPTION_ADDRESS         (0x05)
#define  DHCP_OPTION_ADDRESSMASK     (0x06)
#define  DHCP_OPTION_OPTION          (0x07)
#define  DHCP_OPTION_TYPE            (0x08)
#define  DHCP_OPTION_LIST            (0x80)

// structures and typedefs
typedef struct
{
    uint8_t   used;
    uint16_t  code;
    uint8_t   size[4]; // size-byte / size-min / size-max / size-modulo
    uint8_t   type;
    char      key[64];
} DHCP_OPTION;

// DHCP messages types names
char *dhcp_messages_types[] =
{
    "",
    "discover",
    "offer",
    "request",
    "decline",
    "ack",
    "nak",
    "release",
    "inform",
    "forcerenew",
    "leasequery",
    "leaseunassigned",
    "leaseunknown",
    "leaseactive",
    "bulkleasequery",
    "leasequerydone"
};

// DHCP options types names
char *dhcp_options_types[] =
{
    "none",
    "hexstring",
    "integer",
    "boolean",
    "string",
    "IPv4 address",
    "IPv4 address/netmask",
    "DHCP option",
    "DHCP message type"
};

// DHCP options table (from http://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml)
static DHCP_OPTION dhcp_options[] =
{
    { false,    DHCP_FRAME_RELAYHOPS,        { 0,   1,   1,   0 },  DHCP_OPTION_INTEGER,                         "bootp-relay-hops" },
    { false,    DHCP_FRAME_TRANSACTIONID,    { 0,   4,   4,   0 },  DHCP_OPTION_OPAQUE,                          "bootp-transaction-id" },
    { false,    DHCP_FRAME_STARTTIME,        { 0,   2,   2,   0 },  DHCP_OPTION_INTEGER,                         "bootp-start-time" },
    { false,    DHCP_FRAME_CLIENTADDRESS,    { 0,   4,   4,   0 },  DHCP_OPTION_ADDRESS,                         "bootp-client-address" },
    { false,    DHCP_FRAME_ASSIGNEDADDRESS,  { 0,   4,   4,   0 },  DHCP_OPTION_ADDRESS,                         "bootp-assigned-address" },
    { false,    DHCP_FRAME_SERVERADDRESS,    { 0,   4,   4,   0 },  DHCP_OPTION_ADDRESS,                         "bootp-server-address" },
    { false,    DHCP_FRAME_RELAYADDRESS,     { 0,   4,   4,   0 },  DHCP_OPTION_ADDRESS,                         "bootp-relay-address" },
    { false,    DHCP_FRAME_CLIENTHWADDRESS,  { 0,   6,   6,   0 },  DHCP_OPTION_OPAQUE,                          "client-hardware-address" },
    { false,    DHCP_FRAME_SERVERNAME,       { 0,   1,  63,   0 },  DHCP_OPTION_STRING,                          "bootp-server-name" },
    { false,    DHCP_FRAME_FILENAME,         { 0,   1, 127,   0 },  DHCP_OPTION_STRING,                          "bootp-filename" },
    { false,    0,                           { 0,   0,   0,   0 },  DHCP_OPTION_NONE,                            "pad" },
    { false,    1,                           { 1,   4,   4,   0 },  DHCP_OPTION_ADDRESS,                         "subnet-mask" },
    { false,    2,                           { 1,   4,   4,   0 },  DHCP_OPTION_INTEGER,                         "time-offset" },
    { false,    3,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "routers" },
    { false,    4,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "time-servers" },
    { false,    5,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "name-servers" },
    { false,    6,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "domain-name-servers" },
    { false,    7,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "log-servers" },
    { false,    8,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "cookie-servers" },
    { false,    9,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "lpr-servers" },
    { false,   10,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "impress-servers" },
    { false,   11,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "resource-location-servers" },
    { false,   12,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "hostname" },
    { false,   13,                           { 1,   2,   2,   0 },  DHCP_OPTION_INTEGER,                         "boot-file-size" },
    { false,   14,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "merit-dump-file" },
    { false,   15,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "domain-name" },
    { false,   16,                           { 1,   4,   4,   0 },  DHCP_OPTION_ADDRESS,                         "swap-server" },
    { false,   17,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "root-path" },
    { false,   18,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "extensions-path" },
    { false,   19,                           { 1,   1,   1,   0 },  DHCP_OPTION_BOOLEAN,                         "ip-forwarding" },
    { false,   20,                           { 1,   1,   1,   0 },  DHCP_OPTION_BOOLEAN,                         "non-local-source-routing" },
    { false,   21,                           { 1,   8,   0,   8 },  DHCP_OPTION_ADDRESSMASK | DHCP_OPTION_LIST,  "policy-filters" },
    { false,   22,                           { 1,   2,   2,   0 },  DHCP_OPTION_INTEGER,                         "maximum-datagram-reassembly-size" },
    { false,   23,                           { 1,   1,   1,   0 },  DHCP_OPTION_INTEGER,                         "ip-default-ttl" },
    { false,   24,                           { 1,   4,   4,   0 },  DHCP_OPTION_INTEGER,                         "path-mtu-aging-timeout" },
    { false,   25,                           { 1,   2,   0,   2 },  DHCP_OPTION_INTEGER | DHCP_OPTION_LIST,      "path-mtu-plateau-table" },
    { false,   26,                           { 1,   2,   2,   0 },  DHCP_OPTION_INTEGER,                         "interface-mtu" },
    { false,   27,                           { 1,   1,   1,   0 },  DHCP_OPTION_BOOLEAN,                         "all-subnets-local" },
    { false,   28,                           { 1,   4,   4,   0 },  DHCP_OPTION_ADDRESS,                         "broadcast-address" },
    { false,   29,                           { 1,   1,   1,   0 },  DHCP_OPTION_BOOLEAN,                         "perform-mask-discovery" },
    { false,   30,                           { 1,   1,   1,   0 },  DHCP_OPTION_BOOLEAN,                         "mask-supplier" },
    { false,   31,                           { 1,   1,   1,   0 },  DHCP_OPTION_BOOLEAN,                         "perform-router-discovery" },
    { false,   32,                           { 1,   4,   4,   0 },  DHCP_OPTION_ADDRESS,                         "router-solicitation-address" },
    { false,   33,                           { 1,   8,   0,   8 },  DHCP_OPTION_ADDRESSMASK | DHCP_OPTION_LIST,  "static-routes" },
    { false,   34,                           { 1,   1,   1,   0 },  DHCP_OPTION_BOOLEAN,                         "trailer-encapsulation" },
    { false,   35,                           { 1,   4,   4,   0 },  DHCP_OPTION_INTEGER,                         "arp-cache-timeout" },
    { false,   36,                           { 1,   1,   1,   0 },  DHCP_OPTION_BOOLEAN,                         "ethernet-encapsulation" },
    { false,   37,                           { 1,   1,   1,   0 },  DHCP_OPTION_INTEGER,                         "tcp-default-ttl" },
    { false,   38,                           { 1,   4,   4,   0 },  DHCP_OPTION_INTEGER,                         "tcp-keepalive-interval" },
    { false,   39,                           { 1,   1,   1,   0 },  DHCP_OPTION_BOOLEAN,                         "tcp-keepalive-garbage" },
    { false,   40,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "nis-domain" },
    { false,   41,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "nis-servers" },
    { false,   42,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "ntp-servers" },
    { false,   43,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "vendor-specific-information" },
    { false,   44,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "netbios-name-servers" },
    { false,   45,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "netbios-dgram-distribution-servers" },
    { false,   46,                           { 1,   1,   1,   0 },  DHCP_OPTION_INTEGER,                         "netbios-node-type" },
    { false,   47,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "netbios-scope" },
    { false,   48,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "xwindow-font-servers" },
    { false,   49,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "xwindow-display-managers" },
    { false,   50,                           { 1,   4,   4,   0 },  DHCP_OPTION_ADDRESS,                         "requested-ip-address" },
    { false,   51,                           { 1,   4,   4,   0 },  DHCP_OPTION_INTEGER,                         "address-lease-time" },
    { false,   52,                           { 1,   1,   1,   0 },  DHCP_OPTION_INTEGER,                         "option-overload" },
    { false,   53,                           { 1,   1,   1,   0 },  DHCP_OPTION_TYPE,                            "dhcp-message-type" },
    { false,   54,                           { 1,   4,   4,   0 },  DHCP_OPTION_ADDRESS,                         "server-identifier" },
    { false,   55,                           { 1,   1,   0,   1 },  DHCP_OPTION_OPTION | DHCP_OPTION_LIST,       "parameters-request-list" },
    { false,   56,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "message" },
    { false,   57,                           { 1,   2,   2,   0 },  DHCP_OPTION_INTEGER,                         "max-message-size" },
    { false,   58,                           { 1,   4,   4,   0 },  DHCP_OPTION_INTEGER,                         "renewal-time" },
    { false,   59,                           { 1,   4,   4,   0 },  DHCP_OPTION_INTEGER,                         "rebinding-time" },
    { false,   60,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "vendor-class-identifier" },
    { false,   61,                           { 1,   2,   0,   0 },  DHCP_OPTION_OPAQUE,                          "client-identifier" },
    { false,   62,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "netware-domain" },
    { false,   63,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "netware-option" },
    { false,   64,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "nisp-domain" },
    { false,   65,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "nisp-servers" },
    { false,   66,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "tftp-server" },
    { false,   67,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "boot-filename" },
    { false,   68,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "mobile-ip-home-agents" },
    { false,   69,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "smtp-servers" },
    { false,   70,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "pop3-servers" },
    { false,   71,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "nntp-servers" },
    { false,   72,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "www-servers" },
    { false,   73,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "finger-servers" },
    { false,   74,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "irc-servers" },
    { false,   75,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "streettalk-servers" },
    { false,   76,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "streettalk-directory-servers" },
    { false,   77,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "user-class" },
    { false,   78,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "directory-agent" },
    { false,   79,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "service-scope" },
    { false,   81,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "client-fqdn" },
    { false,   82,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "relay-agent-information" },
    { false,   83,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "isns-configuration" },
    { false,   85,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "nds-servers" },
    { false,   86,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "nds-tree-name" },
    { false,   87,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "nds-context" },
    { false,   88,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "bcmcs-domain" },
    { false,   89,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "bcmcs-servers" },
    { false,   90,                           { 1,   3,   0,   0 },  DHCP_OPTION_OPAQUE,                          "authentication" },
    { false,   91,                           { 1,   4,   4,   0 },  DHCP_OPTION_INTEGER,                         "last-transaction-time" },
    { false,   92,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "associated-addresses" },
    { false,   93,                           { 1,   2,   2,   0 },  DHCP_OPTION_INTEGER,                         "client-system" },
    { false,   94,                           { 1,   3,   3,   0 },  DHCP_OPTION_OPAQUE,                          "client-ndi" },
    { false,   97,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "client-guid" },
    { false,   98,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "user-authentication" },
    { false,   99,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "geoconf-civic" },
    { false,  100,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "tz-posix" },
    { false,  101,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "tz-database" },
    { false,  116,                           { 1,   1,   1,   0 },  DHCP_OPTION_INTEGER,                         "auto-configuration" },
    { false,  117,                           { 1,   2,   0,   2 },  DHCP_OPTION_INTEGER | DHCP_OPTION_LIST,      "name-service-search" },
    { false,  118,                           { 1,   4,   4,   0 },  DHCP_OPTION_ADDRESS,                         "subnet-selection" },
    { false,  119,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "domain-search" },
    { false,  120,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "sip-server" },
    { false,  121,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "classless-route" },
    { false,  122,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "cablelabs-configuration" },
    { false,  123,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "geoconf" },
    { false,  124,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "vi-vendor-class" },
    { false,  125,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "vi-vendor-specific-information" },
    { false,  136,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "pana-agents" },
    { false,  137,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "v4-lost" },
    { false,  138,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "v4-capwap-access-controller" },
    { false,  139,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "v4-address-mos" },
    { false,  140,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "v4-fqdn-mos" },
    { false,  141,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "sip-ua-domain" },
    { false,  142,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "v4-address-andsf" },
    { false,  144,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "v4-geoloc" },
    { false,  145,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "forcerenew-nonce-capable" },
    { false,  146,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "rdnss-selection" },
    { false,  150,                           { 1,   4,   0,   4 },  DHCP_OPTION_ADDRESS | DHCP_OPTION_LIST,      "tftp-servers" },
    { false,  151,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "status-code" },
    { false,  152,                           { 1,   4,   4,   0 },  DHCP_OPTION_INTEGER,                         "base-time" },
    { false,  153,                           { 1,   4,   4,   0 },  DHCP_OPTION_INTEGER,                         "start-time-of-state" },
    { false,  154,                           { 1,   4,   4,   0 },  DHCP_OPTION_INTEGER,                         "query-start-time" },
    { false,  155,                           { 1,   4,   4,   0 },  DHCP_OPTION_INTEGER,                         "query-end-time" },
    { false,  156,                           { 1,   1,   1,   0 },  DHCP_OPTION_INTEGER,                         "dhcp-state" },
    { false,  157,                           { 1,   1,   1,   0 },  DHCP_OPTION_INTEGER,                         "data-source" },
    { false,  158,                           { 1,   5,   0,   0 },  DHCP_OPTION_OPAQUE,                          "v4-pcp-server" },
    { false,  208,                           { 1,   4,   4,   0 },  DHCP_OPTION_OPAQUE,                          "pxelinux-magic" },
    { false,  209,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "configuration-file" },
    { false,  210,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "path-prefix" },
    { false,  211,                           { 1,   4,   4,   0 },  DHCP_OPTION_INTEGER,                         "reboot-time" },
    { false,  212,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "v6-6rd" },
    { false,  213,                           { 1,   1,   0,   0 },  DHCP_OPTION_STRING,                          "v4-access-domain" },
    { false,  220,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "subnet-allocation" },
    { false,  221,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "virtual-subnet-allocation" },
    { false,  224,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-01" },
    { false,  225,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-02" },
    { false,  226,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-03" },
    { false,  227,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-04" },
    { false,  228,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-05" },
    { false,  229,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-06" },
    { false,  230,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-07" },
    { false,  231,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-08" },
    { false,  232,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-09" },
    { false,  233,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-10" },
    { false,  234,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-11" },
    { false,  235,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-12" },
    { false,  236,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-13" },
    { false,  237,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-14" },
    { false,  238,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-15" },
    { false,  239,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-16" },
    { false,  240,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-17" },
    { false,  241,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-18" },
    { false,  242,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-19" },
    { false,  243,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-20" },
    { false,  244,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-21" },
    { false,  245,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-22" },
    { false,  246,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-23" },
    { false,  247,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-24" },
    { false,  248,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-25" },
    { false,  249,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-26" },
    { false,  250,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-27" },
    { false,  251,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-28" },
    { false,  252,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-29" },
    { false,  253,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-30" },
    { false,  254,                           { 1,   1,   0,   0 },  DHCP_OPTION_OPAQUE,                          "private-31" },
    { false,  255,                           { 0,   0,   0,   0 },  DHCP_OPTION_NONE,                            "end" },
};

// list all interpreted keys in JSON payload
void dhcp_listkeys(FILE *output)
{
    int  index = 0, list;
    char type[BUFSIZ], code[8];

    fprintf(output, "key                                  type                                  option\n"
                    "-----------------------------------  ------------------------------------  ------\n");
    while (dhcp_options[index].code != 255)
    {
        if ((dhcp_options[index].type & 0x0f) != DHCP_OPTION_NONE)
        {
            list = (dhcp_options[index].type & DHCP_OPTION_LIST);
            switch (dhcp_options[index].type & 0x0f)
            {
                case DHCP_OPTION_OPAQUE:      sprintf(type, "hexstring%s", list ? "s list" : ""); break;
                case DHCP_OPTION_BOOLEAN:     sprintf(type, "boolean%s", list ? "s list" : ""); break;
                case DHCP_OPTION_INTEGER:     sprintf(type, "integer%s", list ? "s list" : ""); break;
                case DHCP_OPTION_STRING:      sprintf(type, "string%s", list ? "s list" : ""); break;
                case DHCP_OPTION_ADDRESS:     sprintf(type, "IPv4 address%s", list ? "es list" : ""); break;
                case DHCP_OPTION_ADDRESSMASK: sprintf(type, "IPv4 address%s/netmask%s couple%s", list ? "es" : "", list ? "s" : "", list ? "s list" : ""); break;
                case DHCP_OPTION_OPTION:      sprintf(type, "DHCP option%s", list ? "s list" : ""); break;
                case DHCP_OPTION_TYPE:        sprintf(type, "DHCP message type%s", list ? "s list" : ""); break;
            }
            if (dhcp_options[index].code > 0 && dhcp_options[index].code < 255)
            {
                sprintf(code, "%d", dhcp_options[index].code);
            }
            else
            {
                sprintf(code, "-");
            }
            fprintf(output, "%-35.35s  %-36.36s  %s\n", dhcp_options[index].key, type, code);
        }
        index ++;
    }
}

// decode binary DHCP frame to JSON text
static void dhcp_decode_key(const char *key, char *output, int output_size)
{
    if (!key) return;
    snprintf(output + strlen(output), output_size - strlen(output), "\"%s\":", key);
}
static void dhcp_decode_boolean(const char *key, bool value, char *output, int output_size)
{
    dhcp_decode_key(key, output, output_size);
    snprintf(output + strlen(output), output_size - strlen(output), "%s,", value ? "true" : "false");
}
static void dhcp_decode_integer(const char *key, int value, char *output, int output_size)
{
    dhcp_decode_key(key, output, output_size);
    snprintf(output + strlen(output), output_size - strlen(output), "%d,", value);
}
static void dhcp_decode_string(const char *key, char *value, int value_size, char *output, int output_size)
{
    dhcp_decode_key(key, output, output_size);
    if (!value_size)
    {
        snprintf(output + strlen(output), output_size - strlen(output), "\"%s\",", value);
    }
    else if (output_size - strlen(output) - value_size - 3 > 0)
    {
        memset(output + strlen(output), 0, value_size + 4);
        snprintf(output + strlen(output), output_size - strlen(output), "\"");
        memcpy(output + strlen(output), value, value_size);
        snprintf(output + strlen(output), output_size - strlen(output), "\",");
    }
}
static void dhcp_decode_hexstring(const char *key, const uint8_t *value, int value_size, const char *separator, char *output, int output_size)
{
    dhcp_decode_key(key, output, output_size);
    snprintf(output + strlen(output), output_size - strlen(output), "\"");
    for (int index = 0; index < value_size; index ++)
    {
        snprintf(output + strlen(output), output_size - strlen(output), "%02x%s", value[index], separator && (index < value_size - 1) ? separator : "");
    }
    snprintf(output + strlen(output), output_size - strlen(output), "\",");
}
static void dhcp_decode_address(const char *key, uint32_t value, uint32_t mask, char *output, int output_size)
{
    struct in_addr address;

    dhcp_decode_key(key, output, output_size);
    address.s_addr = value;
    snprintf(output + strlen(output), output_size - strlen(output), "\"%s", inet_ntoa(address));
    if (mask)
    {
        address.s_addr = mask;
        snprintf(output + strlen(output), output_size - strlen(output), "/%s", inet_ntoa(address));
    }
    snprintf(output + strlen(output), output_size - strlen(output), "\",");
}
static void dhcp_decode_option(const char *key, int value, char *output, int output_size)
{
    int index = 0;

    dhcp_decode_key(key, output, output_size);
    while (dhcp_options[index].code != 255)
    {
        if (dhcp_options[index].code == value)
        {
            snprintf(output + strlen(output), output_size - strlen(output), "\"%s\",", dhcp_options[index].key);
            return;
        }
        index ++;
    }
    snprintf(output + strlen(output), output_size - strlen(output), "\"%d\",", value);
}
static bool dhcp_decode_type(const char *key, int value, char *output, int output_size)
{
    dhcp_decode_key(key, output, output_size);
    if (value >= DHCP_TYPE_DISCOVER && value <= DHCP_TYPE_LEASEQUERYDONE)
    {
        snprintf(output + strlen(output), output_size - strlen(output), "\"%s\",", dhcp_messages_types[value]);
        return true;
    }
    return false;
}
bool dhcp_decode(DHCP_FRAME *frame, ssize_t frame_size, char *output, ssize_t output_size, char *error, size_t error_size)
{
    DHCP_OPTION *option;
    int         optsize = frame_size - offsetof(DHCP_FRAME, options), offset = 0, index, list, value;
    char        key[8];

    if (!output || (size_t)frame_size < offsetof(DHCP_FRAME, options) || frame->magic != DHCP_FRAME_MAGIC)
    {
        if (error) snprintf(error, error_size, "truncated frame or invalid magic");
        return false;
    }
    if (frame->op != DHCP_FRAME_BOOTREQUEST && frame->op != DHCP_FRAME_BOOTREPLY)
    {
        if (error) snprintf(error, error_size, "invalid BOOTP operation %d", frame->op);
        return false;
    }
    if (frame->htype != 1 || frame->hlen != ETH_ALEN)
    {
        if (error) snprintf(error, error_size, "invalid client hardware address type %d or length %d", frame->htype, frame->hlen);
        return false;
    }
    sprintf(output, "{");
    if (frame->hops)     dhcp_decode_integer("bootp-relay-hops", frame->hops, output, output_size);
    if (frame->xid)      dhcp_decode_hexstring("bootp-transaction-id", (uint8_t *)&frame->xid, 4, NULL, output, output_size);
    if (frame->secs)     dhcp_decode_integer("bootp-start-time", ntohs(frame->secs), output, output_size);
    if (frame->ciaddr)   dhcp_decode_address("bootp-client-address", frame->ciaddr, 0, output, output_size);
    if (frame->yiaddr)   dhcp_decode_address("bootp-assigned-address", frame->yiaddr, 0, output, output_size);
    if (frame->siaddr)   dhcp_decode_address("bootp-server-address", frame->siaddr, 0, output, output_size);
    if (frame->giaddr)   dhcp_decode_address("boot-relay-address", frame->giaddr, 0, output, output_size);
    if (frame->sname[0]) dhcp_decode_string("bootp-server-name", frame->sname, 0, output, output_size);
    if (frame->file[0])  dhcp_decode_string("bootp-filename", frame->file, 0, output, output_size);
    dhcp_decode_hexstring("client-hardware-address", frame->chaddr, ETH_ALEN, ":", output, output_size);
    while (offset < optsize && frame->options[offset] != 255)
    {
        index  = 0;
        option = NULL;
        while (dhcp_options[index].code != 255)
        {
            if (dhcp_options[index].code == frame->options[offset])
            {
                option = &(dhcp_options[index]);
                break;
            }
            index ++;
        }
        if (option)
        {
            if (option->size[0] &&
                ((option->size[3] && frame->options[offset + 1] % option->size[3]) ||
                 (option->size[1] && frame->options[offset + 1] < option->size[1]) ||
                 (option->size[2] && frame->options[offset + 1] > option->size[2])))
            {
                if (error) snprintf(error, error_size, "invalid length %d for DHCP option \"%s\" (min:%d/max:%d/modulo:%d)",
                                    frame->options[offset + 1], option->key, option->size[1], option->size[2], option->size[3]);
                return false;
            }
            if ((list = (option->type & DHCP_OPTION_LIST)))
            {
                dhcp_decode_key(option->key, output, output_size);
                snprintf(output + strlen(output), output_size - strlen(output), "[");
            }
            for (index = 0; index < frame->options[offset + 1]; index += (list && option->size[3] ? option->size[3] : frame->options[offset + 1]))
            {
                switch (option->type & 0x0f)
                {
                    case DHCP_OPTION_OPAQUE:
                        dhcp_decode_hexstring(!list ? option->key : NULL, frame->options + offset + 2 + index, frame->options[offset + 1], NULL, output, output_size);
                        break;

                    case DHCP_OPTION_BOOLEAN:
                        dhcp_decode_boolean(!list ? option->key : NULL, frame->options[offset + 2 + index], output, output_size);
                        break;

                    case DHCP_OPTION_INTEGER:
                        value = 0;
                        for (int shift = 0; shift < min(option->size[1], 4); shift ++)
                        {
                             value <<= 8;
                             value |= frame->options[offset + 2 + index + shift];
                        }
                        dhcp_decode_integer(!list ? option->key : NULL, value, output, output_size);
                        break;

                    case DHCP_OPTION_STRING:
                        dhcp_decode_string(!list ? option->key : NULL, (char *)(frame->options + offset + 2 + index), frame->options[offset + 1], output, output_size);
                        break;

                    case DHCP_OPTION_ADDRESS:
                        dhcp_decode_address(!list ? option->key : NULL, *(uint32_t *)(frame->options + offset + 2 + index), 0, output, output_size);
                        break;

                    case DHCP_OPTION_ADDRESSMASK:
                        dhcp_decode_address(!list ? option->key : NULL, *(uint32_t *)(frame->options + offset + 2 + index), *(uint32_t *)(frame->options + offset + 2 + index + 4), output, output_size);
                        break;

                    case DHCP_OPTION_OPTION:
                        dhcp_decode_option(!list ? option->key : NULL, frame->options[offset + 2 + index], output, output_size);
                        break;

                    case DHCP_OPTION_TYPE:
                        if (!dhcp_decode_type(!list ? option->key : NULL, frame->options[offset + 2 + index], output, output_size))
                        {
                            if (error) snprintf(error, error_size, "unknown DHCP message type %d", frame->options[offset + 2 + index]);
                            return false;
                        }
                        frame->dhcp_type = frame->options[offset + 2 + index];
                        break;
                }
            }
            if (list)
            {
                output[strlen(output) - 1] = ']';
                snprintf(output + strlen(output), output_size - strlen(output), ",");
            }
        }
        else
        {
            sprintf(key, "%d", frame->options[offset]);
            dhcp_decode_hexstring(key, frame->options + offset + 2, frame->options[offset + 1], NULL, output, output_size);
        }
        offset += 1 + (!option || option->size[0] ? frame->options[offset + 1] + 1 : 0);
    }
    output[strlen(output) - 1] = '}';
    memcpy(frame->key, frame->chaddr, ETH_ALEN);
    memcpy(frame->key + ETH_ALEN, (uint8_t *)&(frame->xid), 4);
    frame->key[10] = frame->dhcp_type;
    frame->expire  = time(NULL) + 10;
    return true;
}

// encode JSON text to binary DHCP frame
bool dhcp_encode(char *input, DHCP_FRAME *frame, ssize_t *frame_size, char *error, size_t error_size)
{
    DHCP_OPTION    *option;
    struct in_addr address;
    uint32_t       index = 0, lindex, nkey, nvalue[ETH_ALEN], items;
    char           instring = false, *token = input, *ltoken, *stoken, *key = NULL, *value = NULL;

    if (error) *error = 0;
    while (dhcp_options[index].code != 255)
    {
        dhcp_options[index].used = false;
        index ++;
    }
    memset(frame, 0, sizeof(DHCP_FRAME));
    frame->htype = 1;
    frame->hlen  = ETH_ALEN;
    frame->magic = DHCP_FRAME_MAGIC;
    *frame_size  = 0;
    while (*token)
    {
        if (*token == '"')
        {
            instring = !instring;
        }
        if (!instring && (*token == ' ' || *token == '\t'))
        {
            memmove(token, token + 1, strlen(token));
        }
        else
        {
            token ++;
        }
    }
    if (strlen(input) < 2 || input[0] != '{' || input[strlen(input) - 1] != '}')
    {
        if (error) snprintf(error, error_size, "invalid top-level JSON object near: %32.32s...", input);
        return false;
    }
    if (strlen(input) == 2)
    {
        return true;
    }
    token = input + 1;
    while (*frame_size < (ssize_t)sizeof(frame->options) && *token && *token != '}')
    {
        if (*token != '"')
        {
            if (error) snprintf(error, error_size, "invalid JSON key definition near: %32.32s...", token - 1);
            return false;
        }
        key = ++token;
        while (*token && *token != '"') token ++;
        if (*token != '"' || !*(token + 1) || *(token + 1) != ':')
        {
            if (error) snprintf(error, error_size, "invalid JSON key definition near: %32.32s...", token - 1);
            return false;
        }
        *token = 0;

        option = NULL;
        if ((nkey = atoi(key)) != 0 && (nkey < 1 || nkey > 254))
        {
            if (error) snprintf(error, error_size, "invalid DHCP option \"%d\"", nkey);
            return false;
        }
        index = 0;
        while (dhcp_options[index].code != 255)
        {
            if ((nkey && dhcp_options[index].code == nkey) || (!nkey && !strcasecmp(key, dhcp_options[index].key)))
            {
                option = &(dhcp_options[index]);
                break;
            }
            index ++;
        }
        if (!option)
        {
            if (error) snprintf(error, error_size, "invalid DHCP option \"%s\"", key);
            return false;
        }

        token += 2;
        if (*token != '[' && *token != '"' && !isdigit(*token) && strncasecmp(token, "true", 4) && strncasecmp(token, "false", 5))
        {
            if (error) snprintf(error, error_size, "invalid JSON value definition near: %32.32s...", token - 1);
            return false;
        }
        if (*token == '[')
        {
            if (!(option->type & DHCP_OPTION_LIST))
            {
                if (error) snprintf(error, error_size, "values list not supported for DHCP option \"%s\"", key);
                return false;
            }
            value = ++ token;
            while (*token && *token != ']') token ++;
            if (*token != ']')
            {
                if (error) snprintf(error, error_size, "unclosed JSON list near: %32.32s...", token - 1);
                return false;
            }
            *token = 0;
            token ++;
            if (*token != ',' && *token != '}')
            {
                if (error) snprintf(error, error_size, "invalid JSON format near: %32.32s...", token - 1);
                return false;
            }
            token ++;
        }
        else if (*token == '"')
        {
            if ((option->type & 0x0f) == DHCP_OPTION_BOOLEAN || (option->type & 0x0f) == DHCP_OPTION_INTEGER)
            {
                if (error) snprintf(error, error_size, "invalid value type for DHCP option \"%s\" (string given, should be %s)", key, dhcp_options_types[option->type]);
                return false;
            }
            value = ++ token;
            while (*token && *token != '"') token ++;
            if (*token != '"')
            {
                if (error) snprintf(error, error_size, "unterminated JSON string near: %32.32s...", token - 1);
                return false;
            }
            *token = 0;
            token ++;
            if (*token != ',' && *token != '}')
            {
                if (error) snprintf(error, error_size, "invalid JSON format near: %32.32s...", token - 1);
                return false;
            }
            token ++;
        }
        else if (isdigit(*token))
        {
            value = token;
            if ((option->type & 0x0f) != DHCP_OPTION_INTEGER)
            {
                if (error) snprintf(error, error_size, "invalid value type for DHCP option \"%s\" (integer given, should be %s)", key, dhcp_options_types[option->type]);
                return false;
            }
            while (isdigit(*token)) token ++;
            if (*token != ',' && *token != '}')
            {
                if (error) snprintf(error, error_size, "invalid JSON format near: %32.32s...", token - 1);
                return false;
            }
            *token = 0;
            token ++;
        }
        else
        {
            value = token;
            if ((option->type & 0x0f) != DHCP_OPTION_BOOLEAN)
            {
                if (error) snprintf(error, error_size, "invalid value type for DHCP option \"%s\" (boolean given, should be %s)", key, dhcp_options_types[option->type]);
                return false;
            }
            token += tolower(*token) == 't' ? 4 : 5;
            if (*token != ',' && *token != '}')
            {
                if (error) snprintf(error, error_size, "invalid JSON format near: %32.32s...", token - 1);
                return false;
            }
            *token = 0;
            token ++;
        }
        if (!*value)
        {
            if (error) snprintf(error, error_size, "invalid value for DHCP option \"%s\"", key);
            return false;
        }
        if (option->used)
        {
            continue;
        }
        option->used = true;

        items  = 1;
        ltoken = value;
        while (*ltoken && (ltoken = strchr(ltoken, ','))) { ltoken ++; items ++; }
        ltoken = strtok(value, ",");
        lindex = 0;
        while (ltoken)
        {
            if (*ltoken == '"')
            {
                ltoken ++;
                *(ltoken + strlen(ltoken) - 1) = 0;
            }
            if (!*ltoken)
            {
                if (error) snprintf(error, error_size, "invalid value for DHCP option \"%s\"", key);
                return false;
            }
            switch (option->type & 0x0f)
            {
                case DHCP_OPTION_OPAQUE:
                    if (option->code == DHCP_FRAME_CLIENTHWADDRESS)
                    {
                        if (sscanf(ltoken, "%02x:%02x:%02x:%02x:%02x:%02x", &nvalue[0], &nvalue[1], &nvalue[2], &nvalue[3], &nvalue[4], &nvalue[5]) != ETH_ALEN)
                        {
                            if (error) snprintf(error, error_size, "invalid client hardware address \"%s\"", ltoken);
                            return false;
                        }
                        for (index = 0; index < ETH_ALEN; index ++)
                        {
                            frame->chaddr[index] = nvalue[index] & 0xff;
                        }
                    }
                    else if (option->code == DHCP_FRAME_TRANSACTIONID)
                    {
                        if (sscanf(ltoken, "%08x", &nvalue[0]) != 1)
                        {
                            if (error) snprintf(error, error_size, "invalid transaction id \"%s\"", ltoken);
                            return false;
                        }
                        frame->xid = htonl(nvalue[0]);
                    }
                    else
                    {
                        if ((nvalue[0] = strlen(ltoken)) % 2)
                        {
                            if (error) snprintf(error, error_size, "invalid hexstring format \"%s\"", ltoken);
                            return false;
                        }
                        if (*frame_size > ((ssize_t)sizeof(frame->options) - (2 + (nvalue[0] / 2))))
                        {
                            if (error) snprintf(error, error_size, "not enough space to store DHCP option \"%s\"", key);
                            return false;
                        }
                        frame->options[(*frame_size)++] = option->code;
                        frame->options[(*frame_size)++] = nvalue[0] / 2;
                        for (index = 0; index < nvalue[0]; index += 2)
                        {
                            if (!isxdigit(*(ltoken + index)) || !isxdigit(*(ltoken + index + 1)) || sscanf(ltoken + index, "%02x", &nvalue[1]) != 1)
                            {
                                if (error) snprintf(error, error_size, "invalid hexstring format \"%s\"", ltoken);
                                return false;
                            }
                            frame->options[(*frame_size)++] = nvalue[1] & 0xff;
                        }
                    }
                    break;

                case DHCP_OPTION_BOOLEAN:
                    if (!lindex)
                    {
                        if (*frame_size > (ssize_t)sizeof(frame->options) - (2 + (option->size[1] * items)))
                        {
                            if (error) snprintf(error, error_size, "not enough space to store DHCP option \"%s\"", key);
                            return false;
                        }
                        frame->options[(*frame_size)++] = option->code;
                        frame->options[(*frame_size)++] = option->size[1] * items;
                    }
                    frame->options[(*frame_size)++] = (tolower(*ltoken) == 't');
                    break;

                case DHCP_OPTION_INTEGER:
                    if (option->code == DHCP_FRAME_RELAYHOPS)
                    {
                        frame->hops = atoi(ltoken) & 0xff;
                    }
                    else if (option->code == DHCP_FRAME_STARTTIME)
                    {
                        frame->secs = htons(atoi(ltoken) & 0xffff);
                    }
                    else
                    {
                        if (!lindex)
                        {
                            if (*frame_size > (ssize_t)sizeof(frame->options) - (2 + (option->size[1] * items)))
                            {
                                if (error) snprintf(error, error_size, "not enough space to store DHCP option \"%s\"", key);
                                return false;
                            }
                            frame->options[(*frame_size)++] = option->code;
                            frame->options[(*frame_size)++] = option->size[1] * items;
                        }
                        nvalue[0] = atoi(ltoken);
                        for (index = 0; index < option->size[1]; index ++)
                        {
                            frame->options[(*frame_size)++] = (nvalue[0] >> ((option->size[1] - 1 - index) * 8)) & 0xff;
                        }
                    }
                    break;

                case DHCP_OPTION_STRING:
                    switch (option->code)
                    {
                        case DHCP_FRAME_SERVERNAME:
                            snprintf(frame->sname, sizeof(frame->sname), "%s", ltoken);
                            break;

                        case DHCP_FRAME_FILENAME:
                            snprintf(frame->file, sizeof(frame->file), "%s", ltoken);
                            break;

                        default:
                            nvalue[0] = strlen(ltoken);
                            if (*frame_size > (ssize_t)sizeof(frame->options) - (2 + nvalue[0]))
                            {
                                if (error) snprintf(error, error_size, "not enough space to store DHCP option \"%s\"", key);
                                return false;
                            }
                            frame->options[(*frame_size)++] = option->code;
                            frame->options[(*frame_size)++] = nvalue[0];
                            memcpy(frame->options + *frame_size, ltoken, nvalue[0]);
                            *frame_size += nvalue[0];
                            break;
                    }
                    break;

                case DHCP_OPTION_ADDRESS:
                    if (!inet_aton(ltoken, &address))
                    {
                        if (error) snprintf(error, error_size, "invalid IPv4 address \"%s\" for DHCP option \"%s\"", ltoken, key);
                        return false;
                    }
                    switch (option->code)
                    {
                        case DHCP_FRAME_CLIENTADDRESS:
                            frame->ciaddr = address.s_addr;
                            break;

                        case DHCP_FRAME_ASSIGNEDADDRESS:
                            frame->yiaddr = address.s_addr;
                            break;

                        case DHCP_FRAME_SERVERADDRESS:
                            frame->siaddr = address.s_addr;
                            break;

                        case DHCP_FRAME_RELAYADDRESS:
                            frame->giaddr = address.s_addr;
                            break;

                        default:
                            if (!lindex)
                            {
                                if (*frame_size > (ssize_t)sizeof(frame->options) - (2 + (option->size[1] * items)))
                                {
                                    if (error) snprintf(error, error_size, "not enough space to store DHCP option \"%s\"", key);
                                    return false;
                                }
                                frame->options[(*frame_size)++] = option->code;
                                frame->options[(*frame_size)++] = option->size[1] * items;
                            }
                            memcpy(frame->options + *frame_size, &(address.s_addr), option->size[1]);
                            *frame_size += option->size[1];
                            break;
                    }
                    break;

                case DHCP_OPTION_ADDRESSMASK:
                    if (!lindex)
                    {
                        if (*frame_size > (ssize_t)sizeof(frame->options) - (2 + (option->size[1] * items)))
                        {
                            if (error) snprintf(error, error_size, "not enough space to store DHCP option \"%s\"", key);
                            return false;
                        }
                        frame->options[(*frame_size)++] = option->code;
                        frame->options[(*frame_size)++] = option->size[1] * items;
                    }
                    if (!(stoken = strchr(ltoken, '/')))
                    {
                        if (error) snprintf(error, error_size, "invalid address/netmask format \"%s\" for DHCP option \"%s\"", ltoken, key);
                        return false;
                    }
                    *stoken ++ = 0;
                    if (!inet_aton(ltoken, &address))
                    {
                        if (error) snprintf(error, error_size, "invalid IPv4 address \"%s\" for DHCP option \"%s\"", ltoken, key);
                        return false;
                    }
                    memcpy(frame->options + *frame_size, &(address.s_addr), option->size[1] / 2);
                    *frame_size += option->size[1] / 2;
                    if (!inet_aton(stoken, &address))
                    {
                        if (error) snprintf(error, error_size, "invalid IPv4 netmask \"%s\" for DHCP option \"%s\"", ltoken, key);
                        return false;
                    }
                    memcpy(frame->options + *frame_size, &(address.s_addr), option->size[1] / 2);
                    *frame_size += option->size[1] / 2;
                    break;

                case DHCP_OPTION_OPTION:
                    if (!lindex)
                    {
                        if (*frame_size > (ssize_t)sizeof(frame->options) - (2 + (option->size[1] * items)))
                        {
                            if (error) snprintf(error, error_size, "not enough space to store DHCP option \"%s\"", key);
                            return false;
                        }
                        frame->options[(*frame_size)++] = option->code;
                        frame->options[(*frame_size)++] = option->size[1] * items;
                    }
                    if ((nvalue[0] = atoi(ltoken)) != 0 && (nvalue[0] < 1 || nvalue[0] > 254))
                    {
                        if (error) snprintf(error, error_size, "invalid DHCP option %d", nvalue[0]);
                        return false;
                    }
                    index = 0;
                    while (dhcp_options[index].code != 255)
                    {
                        if ((nvalue[0] && dhcp_options[index].code == nvalue[0]) || (!nvalue[0] && dhcp_options[index].code < 255 && !strcasecmp(ltoken, dhcp_options[index].key)))
                        {
                            frame->options[(*frame_size)++] = dhcp_options[index].code;
                            break;
                        }
                        index ++;
                    }
		    if (dhcp_options[index].code == 255)
                    {
                        if (error) snprintf(error, error_size, "unknown DHCP option \"%s\"", ltoken);
                        return false;
                    }
                    break;

                case DHCP_OPTION_TYPE:
                    if (*frame_size > (ssize_t)sizeof(frame->options) - 3)
                    {
                        if (error) snprintf(error, error_size, "not enough space to store DHCP option \"%s\"", key);
                        return false;
                    }
                    for (index = DHCP_TYPE_DISCOVER; index <= DHCP_TYPE_LEASEQUERYDONE; index ++)
                    {
                        if (!strcasecmp(ltoken, dhcp_messages_types[index])) break;
                    }
                    if (index > DHCP_TYPE_LEASEQUERYDONE)
                    {
                        if (error) snprintf(error, error_size, "unknown DHCP message type \"%s\"", ltoken);
                        return false;
                    }
                    frame->options[(*frame_size)++] = option->code;
                    frame->options[(*frame_size)++] = option->size[1];
                    frame->options[(*frame_size)++] = frame->dhcp_type = index;
                    break;
            }
            ltoken = strtok(NULL, ",");
            lindex ++;
        }
    }
    if (!frame->dhcp_type)
    {
        if (error) snprintf(error, error_size, "undefined DHCP message type");
        return false;
    }
    if (!memcmp(frame->chaddr, "\x00\x00\x00\x00\x00\x00", ETH_ALEN))
    {
        if (error) snprintf(error, error_size, "undefined client hardware address");
        return false;
    }
    if (!frame->xid)
    {
        frame->xid = lrand48();
    }
    frame->options[(*frame_size)++] = 255;
    *frame_size += offsetof(DHCP_FRAME, options);
    *frame_size  = max(300, *frame_size);
    memcpy(frame->key, frame->chaddr, ETH_ALEN);
    memcpy(frame->key + ETH_ALEN, (uint8_t *)&(frame->xid), 4);
    switch (frame->dhcp_type)
    {
        case DHCP_TYPE_OFFER: frame->key[10] = DHCP_TYPE_DISCOVER; break;
        case DHCP_TYPE_ACK:   frame->key[10] = DHCP_TYPE_REQUEST; break;
        case DHCP_TYPE_NAK:   frame->key[10] = DHCP_TYPE_REQUEST; break;
        default:              frame->key[10] = frame->dhcp_type; break;
    }
    switch (frame->dhcp_type)
    {
        case DHCP_TYPE_DISCOVER:
        case DHCP_TYPE_REQUEST:
        case DHCP_TYPE_DECLINE:
        case DHCP_TYPE_RELEASE:
        case DHCP_TYPE_INFORM:
            frame->op = DHCP_FRAME_BOOTREQUEST;
            break;

        case DHCP_TYPE_OFFER:
        case DHCP_TYPE_ACK:
        case DHCP_TYPE_NAK:
        default:
            frame->op = DHCP_FRAME_BOOTREPLY;
            break;
    }
    return true;
}
