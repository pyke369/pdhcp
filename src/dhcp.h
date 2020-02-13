#ifndef __DHCP_INCLUDE
#define __DHCP_INCLUDE

// includes
#include <stdint.h>

// defines
#define  DHCP_FRAME_BOOTREQUEST     (0x01)
#define  DHCP_FRAME_BOOTREPLY       (0x02)

#define  DHCP_TYPE_DISCOVER         (0x01)
#define  DHCP_TYPE_OFFER            (0x02)
#define  DHCP_TYPE_REQUEST          (0x03)
#define  DHCP_TYPE_DECLINE          (0x04)
#define  DHCP_TYPE_ACK              (0x05)
#define  DHCP_TYPE_NAK              (0x06)
#define  DHCP_TYPE_RELEASE          (0x07)
#define  DHCP_TYPE_INFORM           (0x08)
#define  DHCP_TYPE_FORCERENEW       (0x09)
#define  DHCP_TYPE_LEASEQUERY       (0x0a)
#define  DHCP_TYPE_LEASEUNASSIGNED  (0x0b)
#define  DHCP_TYPE_LEASEUNKNOWN     (0x0c)
#define  DHCP_TYPE_LEASEACTIVE      (0x0d)
#define  DHCP_TYPE_BULKLEASEQUERY   (0x0e)
#define  DHCP_TYPE_LEASEQUERYDONE   (0x0f)

// structures and typedefs
#pragma  pack(push, 1)
typedef struct
{
    uint8_t   op;
    uint8_t   htype;
    uint8_t   hlen;
    uint8_t   hops;
    uint32_t  xid;
    uint16_t  secs;
    uint16_t  flags;
    uint32_t  ciaddr;
    uint32_t  yiaddr;
    uint32_t  siaddr;
    uint32_t  giaddr;
    uint8_t   chaddr[16];
    char      sname[64];
    char      file[128];
    uint32_t  magic;
    uint8_t   options[2048];

    // extra information
    uint8_t   dhcp_type;
    struct    sockaddr_in remote;
    uint8_t   key[11];
    double    start;
    time_t    expire;
} DHCP_FRAME;
#pragma  pack(pop)

// function prototypes
extern char *dhcp_messages_types[];
void   dhcp_listkeys(FILE *);
void   dhcp_setkey(DHCP_FRAME *);
bool   dhcp_decode(DHCP_FRAME *, ssize_t, char *, ssize_t, char *, size_t);
bool   dhcp_encode(char *, DHCP_FRAME *, ssize_t *, char *, size_t);

#endif
