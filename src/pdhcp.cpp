// This file is part of pdhcp
// Copyright (c) 2015 Pierre-Yves Kerembellec <py.kerembellec@gmail.com>

// includes
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>
#include <errno.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unordered_map>

#include <ev.h>
#include <util.h>
#include <dhcp.h>

// defines
#define  PDHCP_VERSION                 "1.0.4"
#define  PDHCP_MAX_WORKERS             (32)
#define  PDHCP_DEFAULT_PIDFILE         ("/var/run/pdhcp.pid")
#define  PDHCP_DEFAULT_ADDRESS         ("0.0.0.0")
#define  PDHCP_DEFAULT_SERVER_PORT     ("67")
#define  PDHCP_DEFAULT_CLIENT_PORT     (68)
#define  PDHCP_DEFAULT_CLIENT_RETRIES  (3)

// structures and typedefs
typedef struct
{
    ev_io  stdout_watcher, stderr_watcher;
    int    stdin, stdout, stderr;
    time_t active;
    pid_t  pid;
} PDHCP_WORKER;

struct hrq
{
    long operator()(const uint8_t *d) const
    {
        long h = *d, index;
        for (++ d, index = 1; index < 11; ++ d, index ++) h = (h << 5) - h + *d;
        return h;
    }
};
struct cmprq
{
    bool operator()(const uint8_t *d1, const uint8_t *d2) const
    {
        return !memcmp(d1, d2, 11);
    }
};
typedef  std::unordered_map<uint8_t *, DHCP_FRAME *, hrq, cmprq>  PDHCP_REQUESTS;
typedef  PDHCP_REQUESTS::iterator                                 PDHCP_REQUESTS_IT;

struct udpcksum
{
    uint32_t      source;
    uint32_t      destination;
    uint8_t       reserved;
    uint8_t       protocol;
    uint16_t      length;
    struct udphdr udp_header;
};

// globals
PDHCP_WORKER   workers[PDHCP_MAX_WORKERS];
PDHCP_REQUESTS requests;
struct ev_loop *loop;
ev_io          service_watcher;
ev_timer       tick_watcher;
time_t         next = 0, delta = 2;
uint32_t       xid = 0;
int            workers_count = 1, retries = 3, service = -1, verbose = false;
char           *pidfile = NULL, *address = NULL, *port = NULL, *interface = NULL, *backend = NULL, *user = NULL, *group = NULL, *extra = NULL;

// worker stdout handler
void worker_stdout_handler(struct ev_loop *loop, struct ev_io *watcher, int events)
{
    PDHCP_WORKER      *worker = (PDHCP_WORKER *)watcher->data;
    DHCP_FRAME        frame;
    PDHCP_REQUESTS_IT request;
    ssize_t           size;
    char              received[BUFSIZ], message[256], *token;

    memset(received, 0, sizeof(received));
    if (!(size = read(worker->stdout, received, sizeof(received))))
    {
        ev_io_stop(loop, watcher);
        worker->active = 0;
        return;
    }
    if (size > 0)
    {
        token = strtok(received, "\r\n");
        while (token)
        {
            if (dhcp_encode(token, &frame, &size, message, sizeof(message)))
            {
                worker->active = time(NULL);
                if (size)
                {
                    log_message(LOG_INFO, "dhcp-%s for %02x:%02x:%02x:%02x:%02x:%02x/%08x received from backend worker %d",
                                dhcp_messages_types[frame.dhcp_type],
                                frame.chaddr[0], frame.chaddr[1], frame.chaddr[2], frame.chaddr[3], frame.chaddr[4], frame.chaddr[5],
                                ntohl(frame.xid), workers->pid);
                    if ((request = requests.find(frame.key)) == requests.end())
                    {
                        log_message(LOG_WARNING, "no matching pending request for %02x:%02x:%02x:%02x:%02x:%02x/%08x, ignoring response from backend worker %d",
                                    frame.chaddr[0], frame.chaddr[1], frame.chaddr[2], frame.chaddr[3], frame.chaddr[4], frame.chaddr[5],
                                    ntohl(frame.xid), workers->pid);
                        return;
                    }
                    if (frame.giaddr)
                    {
                        request->second->remote.sin_addr.s_addr = frame.giaddr;
                    }
                    else
                    {
                        request->second->remote.sin_addr.s_addr = INADDR_BROADCAST;
                    }
                    if (sendto(service, (uint8_t *)&frame, size, 0, (struct sockaddr *)&request->second->remote, sizeof(request->second->remote)) == size)
                    {
                        log_message(LOG_INFO, "dhcp-%s for %02x:%02x:%02x:%02x:%02x:%02x/%08x sent to %s:%d",
                                    dhcp_messages_types[frame.dhcp_type],
                                    frame.chaddr[0], frame.chaddr[1], frame.chaddr[2], frame.chaddr[3], frame.chaddr[4], frame.chaddr[5],
                                    ntohl(frame.xid), inet_ntoa(request->second->remote.sin_addr), ntohs(request->second->remote.sin_port));
                        SFREE(request->second);
                        requests.erase(request);
                    }
                    else
                    {
                        log_message(LOG_WARNING, "error sending dhcp-%s for %02x:%02x:%02x:%02x:%02x:%02x/%08x to %s:%d: %s",
                                    dhcp_messages_types[frame.dhcp_type],
                                    frame.chaddr[0], frame.chaddr[1], frame.chaddr[2], frame.chaddr[3], frame.chaddr[4], frame.chaddr[5],
                                    ntohl(frame.xid), inet_ntoa(request->second->remote.sin_addr), ntohs(request->second->remote.sin_port),
                                    strerror(errno));
                    }
                }
            }
            else
            {
                log_message(LOG_WARNING, "received invalid JSON from backend worker %d: %s", worker->pid, message);
            }
            token = strtok(NULL, "\r\n");
        }
    }
}

// worker stderr handler
void worker_stderr_handler(struct ev_loop *loop, struct ev_io *watcher, int events)
{
    PDHCP_WORKER *worker = (PDHCP_WORKER *)watcher->data;
    ssize_t      size;
    char         received[BUFSIZ], *token;

    memset(received, 0, sizeof(received));
    if (!(size = read(worker->stderr, received, sizeof(received))))
    {
        ev_io_stop(loop, watcher);
        worker->active = 0;
        return;
    }
    if (size > 0)
    {
        token = strtok(received, "\r\n");
        while (token)
        {
            log_message(LOG_WARNING, "worker %d: %s", worker->pid, token);
            token = strtok(NULL, "\r\n");
        }
    }
}

// service handler
void service_handler(struct ev_loop *loop, struct ev_io *watcher, int events)
{
    DHCP_FRAME         *frame, *mframe;
    socklen_t          ssize;
    ssize_t            size;
    time_t             now;
    int                index, count = 0, target;
    uint8_t            packet[BUFSIZ];
    char               output[BUFSIZ], message[256];

    now   = time(NULL);
    ssize = sizeof(frame->remote);
    frame = (DHCP_FRAME *)packet;
    if ((size = recvfrom(service, packet, sizeof(packet), 0, (struct sockaddr *)&frame->remote, &ssize)) > 0)
    {
        if (backend)
        {
            if (dhcp_decode(frame, size, output, sizeof(output), message, sizeof(message)) && frame->op == DHCP_FRAME_BOOTREQUEST)
            {
                log_message(LOG_INFO, "dhcp-%s received from %s:%d for %02x:%02x:%02x:%02x:%02x:%02x/%08x",
                            dhcp_messages_types[frame->dhcp_type], inet_ntoa(frame->remote.sin_addr), ntohs(frame->remote.sin_port),
                            frame->chaddr[0], frame->chaddr[1], frame->chaddr[2], frame->chaddr[3], frame->chaddr[4], frame->chaddr[5],
                            ntohl(frame->xid));
                if ((mframe = (DHCP_FRAME *)malloc(sizeof(DHCP_FRAME))))
                {
                    memcpy(mframe, frame, sizeof(DHCP_FRAME));
                    requests[mframe->key] = mframe;
                    for (index = 0; index < PDHCP_MAX_WORKERS; index ++)
                    {
                        if (workers[index].pid && workers[index].active >= (now - 5)) count ++;
                    }
                    if (!count)
                    {
                        log_message(LOG_ERR, "no available backend worker to process request");
                        return;
                    }
                    target = frame->chaddr[5] % count;
                    for (index = 0; index < PDHCP_MAX_WORKERS; index ++)
                    {
                        if (workers[index].pid && workers[index].active >= (now - 5))
                        {
                            if (!target)
                            {
                                strcat(output, "\n");
                                if (write(workers[index].stdin, output, strlen(output)) == (ssize_t)strlen(output))
                                {
                                    log_message(LOG_INFO, "dhcp-%s for %02x:%02x:%02x:%02x:%02x:%02x/%08x forwarded to backend worker %d",
                                                dhcp_messages_types[frame->dhcp_type],
                                                frame->chaddr[0], frame->chaddr[1], frame->chaddr[2], frame->chaddr[3], frame->chaddr[4], frame->chaddr[5],
                                                ntohl(frame->xid), workers[index].pid);
                                }
                                break;
                            }
                            target --;
                        }
                    }
                }
            }
            else
            {
                log_message(LOG_WARNING, "invalid DHCP frame received from %s:%d: %s", inet_ntoa(frame->remote.sin_addr), ntohs(frame->remote.sin_port), message);
            }
        }
        else
        {
            struct ether_header *eth_header;
            struct iphdr        *ip_header;
            struct udphdr       *udp_header;

            eth_header = (struct ether_header *)packet;
            if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
            {
                ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));
                if (ip_header->protocol == IPPROTO_UDP)
                {
                    udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip_header->ihl * sizeof(uint32_t)));
                    if (ntohs(udp_header->dest) == PDHCP_DEFAULT_CLIENT_PORT)
                    {
                        frame = (DHCP_FRAME *)(packet + sizeof(struct ether_header) + (ip_header->ihl * sizeof(uint32_t)) + sizeof(udphdr));
                        frame->remote.sin_addr.s_addr = ip_header->saddr;
                        if (dhcp_decode(frame, ntohs(udp_header->len) - sizeof(struct udphdr), output, sizeof(output), message, sizeof(message)))
                        {
                            if (frame->op == DHCP_FRAME_BOOTREPLY && frame->dhcp_type == DHCP_TYPE_OFFER && frame->xid == xid && !memcmp(frame->chaddr, get_mac_address(interface, true), ETH_ALEN))
                            {
                                if (verbose)
                                {
                                    log_message(LOG_INFO, "dhcp-offer received from %s:%d for %02x:%02x:%02x:%02x:%02x:%02x/%08x",
                                                inet_ntoa(frame->remote.sin_addr), ntohs(udp_header->source),
                                                frame->chaddr[0], frame->chaddr[1], frame->chaddr[2], frame->chaddr[3], frame->chaddr[4], frame->chaddr[5], ntohl(frame->xid));
                                }
                                printf("%s\n", output);
                                exit(0);
                            }
                        }
                        else if (verbose)
                        {
                            log_message(LOG_WARNING, "invalid DHCP frame received from %s:%d: %s", inet_ntoa(frame->remote.sin_addr), ntohs(udp_header->source), message);
                        }
                    }
                }
            }
        }
    }
}

// periodic handler
void tick_handler(struct ev_loop *loop, struct ev_timer *watcher, int events)
{
    time_t now = time(NULL);

    if (backend)
    {
        PDHCP_WORKER *worker = NULL;
        pid_t        pid;
        int          status, index1, index2, count = 0;

        // reap exited workers
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
        {
            for (index1 = 0; index1 < PDHCP_MAX_WORKERS; index1 ++)
            {
                if (workers[index1].pid == pid)
                {
                    ev_io_stop(loop, &(workers[index1].stdout_watcher));
                    ev_io_stop(loop, &(workers[index1].stderr_watcher));
                    close(workers[index1].stdin);
                    close(workers[index1].stdout);
                    close(workers[index1].stderr);
                    memset(&(workers[index1]), 0, sizeof(PDHCP_WORKER));
                }
            }
        }

        // start new workers if needed
        for (index1 = 0; index1 < PDHCP_MAX_WORKERS; index1 ++)
        {
            if (workers[index1].pid) count ++;
        }
        for (index2 = count; index2 < workers_count; index2 ++)
        {
            worker = NULL;
            for (index1 = 0; index1 < PDHCP_MAX_WORKERS; index1 ++)
            {
                if (!workers[index1].pid)
                {
                    worker = &(workers[index1]);
                    break;
                }
            }
            if (worker && (worker->pid = exec_command(backend, user, group, &(worker->stdin), &(worker->stdout), &(worker->stderr))))
            {
                ev_io_init(&(worker->stdout_watcher), worker_stdout_handler, worker->stdout, EV_READ);
                worker->stdout_watcher.data = worker;
                ev_io_start(loop, &(worker->stdout_watcher));
                ev_io_init(&(worker->stderr_watcher), worker_stderr_handler, worker->stderr, EV_READ);
                worker->stderr_watcher.data = worker;
                ev_io_start(loop, &(worker->stderr_watcher));
                log_message(LOG_INFO, "spawned backend worker %d", worker->pid);
            }
        }

        // reap expired requests
        for (PDHCP_REQUESTS_IT it = requests.begin(), ite = requests.end(); it != ite; )
        {
            if (it->second->expire < now)
            {
                log_message(LOG_WARNING, "no backend response to dhcp-%s for %02x:%02x:%02x:%02x:%02x:%02x/%08x", dhcp_messages_types[it->second->dhcp_type],
                            it->second->chaddr[0], it->second->chaddr[1], it->second->chaddr[2], it->second->chaddr[3], it->second->chaddr[4], it->second->chaddr[5], ntohl(it->second->xid));
                SFREE(it->second);
                requests.erase(it ++);
            }
            else
            {
                ++ it;
            }
        }
    }

    else
    {
        if (!retries)
        {
            log_message(LOG_WARNING, "no valid response from DHCP server - exiting");
            exit(1);
        }

        // send DHCP discover message
        if (!next || now >= next)
        {
            struct ether_header *eth_header;
            struct iphdr        *ip_header;
            struct udphdr       *udp_header;
            struct udpcksum     *udp_cksum;
            DHCP_FRAME          *frame;
            struct sockaddr_ll  device;
            ssize_t             size, offset = 0;
            uint8_t             packet[sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(DHCP_FRAME)],
                                check[sizeof(udpcksum) + sizeof(udphdr) + sizeof(DHCP_FRAME)];
            char                request[BUFSIZ], message[256];

            memset(packet, 0, sizeof(packet));
            memset(check, 0, sizeof(check));
            eth_header = (struct ether_header *)packet;
            ip_header  = (struct iphdr *)(packet + sizeof(struct ether_header));
            udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
            udp_cksum  = (struct udpcksum *)check;
            frame      = (DHCP_FRAME *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr));

            offset += snprintf(request + offset, sizeof(request) - offset, "{\"client-hardware-address\":\"%s\"", get_mac_address(interface, false));
            if (extra)
            {
                offset += snprintf(request + offset, sizeof(request) - offset, ",%s", extra);
            }
            if (!gethostname(message, sizeof(message)))
            {
                offset += snprintf(request + offset, sizeof(request) - offset, ",\"hostname\":\"%s\"", message);
            }
            sprintf(message, "%s", get_ip_address(interface, false));
            if (strcmp(message, "0.0.0.0"))
            {
                offset += snprintf(request + offset, sizeof(request) - offset, ",\"bootp-client-address\":\"%s\"", message);
            }
            offset += snprintf(request + offset, sizeof(request) - offset,
                               ",\"dhcp-message-type\":\"discover\",\"parameters-request-list\":[\"hostname\",\"subnet-mask\",\"routers\",\"domain-name\",\"domain-name-servers\",\"time-offset\",\"ntp-servers\"]}");
            if (!dhcp_encode(request, frame, &size, message, sizeof(message)))
            {
                log_message(LOG_CRIT, "error building DHCP request: %s - aborting", message);
                exit(1);
            }
            if (frame->op != DHCP_FRAME_BOOTREQUEST)
            {
                log_message(LOG_CRIT, "only DHCP requests can be sent in client mode (dhcp-%s is a DHCP response message) - aborting",  dhcp_messages_types[frame->dhcp_type]);
                exit(1);
            }
            xid = frame->xid;

            memset(eth_header->ether_dhost, 0xff, ETH_ALEN);
            memcpy(eth_header->ether_shost, get_mac_address(interface, true), ETH_ALEN);
            eth_header->ether_type  = htons(ETHERTYPE_IP);

            ip_header->version      = 4;
            ip_header->ihl          = sizeof(struct iphdr) / sizeof (uint32_t);
            ip_header->tos          = IPTOS_LOWDELAY;
            ip_header->ttl          = 128;
            ip_header->protocol     = IPPROTO_UDP;
            ip_header->daddr        = INADDR_BROADCAST;
            ip_header->tot_len      = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + size);
            ip_header->check        = compute_crc16((uint8_t *)ip_header, sizeof(struct iphdr));

            udp_header->source      = ntohs(PDHCP_DEFAULT_CLIENT_PORT);
            udp_header->dest        = ntohs(atoi(port));
            udp_header->len         = htons(sizeof(struct udphdr) + size);
            udp_cksum->source       = ip_header->saddr;
            udp_cksum->destination  = ip_header->daddr;
            udp_cksum->protocol     = ip_header->protocol;
            udp_cksum->length       = htons(sizeof(struct udphdr) + size);
            memcpy(check + sizeof(struct udpcksum), udp_header, sizeof(struct udphdr));
            memcpy(check + sizeof(struct udpcksum) + sizeof(struct udphdr), frame, size);
            udp_header->check       = compute_crc16(check, sizeof(struct udpcksum) + sizeof(struct udphdr) + size);

            memset(&device, 0, sizeof(device));
            device.sll_family  = AF_PACKET;
            device.sll_ifindex = if_nametoindex(interface);
            device.sll_halen   = ETH_ALEN;
            memcpy(device.sll_addr, eth_header->ether_shost, ETH_ALEN);

            if (sendto(service, packet, (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + size), 0, (struct sockaddr *)&device, sizeof(device)) < 0)
            {
                log_message(LOG_CRIT, "error sending DHCP request: %s - aborting", strerror(errno));
                exit(1);
            }
            if (verbose)
            {
                log_message(LOG_INFO, "dhcp-%s for %02x:%02x:%02x:%02x:%02x:%02x/%08x sent to 255.255.255.255:%d",
                            dhcp_messages_types[frame->dhcp_type],
                            frame->chaddr[0], frame->chaddr[1], frame->chaddr[2], frame->chaddr[3], frame->chaddr[4], frame->chaddr[5], ntohl(frame->xid), atoi(port));
            }

            next = now + delta;
            delta *= 1.5;
            retries --;
        }
    }
}

// main program entry
int main(int argc, char **argv)
{
    // parse command-line arguments
    {
        char *token;
        int  option;

        static struct option options[] =
        {
            {"help",        0, NULL, 'h'},
            {"version",     0, NULL, 'V'},
            {"verbose",     0, NULL, 'v'},
            {"listkeys",    0, NULL, 'l'},
            {"port",        1, NULL, 'p'},
            {"address",     1, NULL, 'a'},
            {"interface",   1, NULL, 'i'},
            {"retries",     1, NULL, 'r'},
            {"request",     1, NULL, 'R'},
            {"backend",     1, NULL, 'b'},
            {"credentials", 1, NULL, 'c'},
            {"workers",     1, NULL, 'n'},
            {"facility",    1, NULL, 'f'},
            {"pidfile",     1, NULL, 'z'},
            {NULL,          0, NULL,  0 }
        };
        while ((option = getopt_long(argc, argv, "hVvlp:a:i:r:R:b:c:n:f:z:", options, NULL)) != -1)
        {
            switch (option)
            {
                case 'h':
                    fprintf
                    (
                        stderr,
                        "Usage: pdhcp [OPTIONS...]\n\n"
                        "-h, --help                        show this help screen and exit\n"
                        "-V, --version                     display program version and exit\n"
                        "-v, --verbose                     \n"
                        "-l, --listkeys                    list all keys useable in the communication protocol with workers\n"
                        "-p, --port <port>                 use specified server UDP port (default: %s)\n"
                        "-a, --address <address>           use specified server address (default: %s)\n"
                        "-i, --interface <name>            use specified interface (default: first available)\n"
                        "-r, --retries <count>             set requests retry count in client mode (default: %d)\n"
                        "-R, --request <reqspec>           add specified DHCP attributes to request in client mode\n"
                        "-b, --backend <command>           run backend command in server mode (default: client mode)\n"
                        "-c, --credentials <user[:group]>  use specified credentials for backend command in server mode (default: main process credentials)\n"
                        "-n, --workers <count>             set workers count in server mode (default: 1)\n"
                        "-f, --facility <facility>         set syslog logging facility (default: daemon)\n"
                        "-z, --pidfile <path>              use specified path to store PID (default: %s)\n",
                        PDHCP_DEFAULT_SERVER_PORT,
                        PDHCP_DEFAULT_ADDRESS,
                        PDHCP_DEFAULT_CLIENT_RETRIES,
                        PDHCP_DEFAULT_PIDFILE
                    );
                    return 1;
                    break;

                case 'V':
                    fprintf(stderr, "pdhcp v" PDHCP_VERSION "\n");
                    return 0;
                    break;

                case 'v':
                    verbose = true;
                    break;

                case 'l':
                    dhcp_listkeys(stdout);
                    return 0;
                    break;

                case 'p':
                    port = strdup(optarg);
                    break;

                case 'a':
                    address = strdup(optarg);
                    break;

                case 'i':
                    interface = strdup(optarg);
                    break;

                case 'r':
                    retries = min(5, max(1, atoi(optarg)));
                    break;

                case 'R':
                    extra = strdup(optarg);
                    if (strlen(extra) < 2 || extra[0] != '{' || extra[strlen(extra) - 1] != '}')
                    {
                        log_message(LOG_CRIT, "invalid request specification %s - aborting", extra);
                        exit(1);
                    }
                    extra[strlen(extra) - 1] = 0;
                    memmove(extra, extra + 1, strlen(extra));
                    break;

                case 'b':
                    backend = strdup(optarg);
                    break;

                case 'c':
                    if ((token = strchr(optarg, ':')))
                    {
                        *token = 0;
                        group = strdup(token + 1);
                    }
                    user = strdup(optarg);
                    break;

                case 'n':
                    workers_count = min(PDHCP_MAX_WORKERS, max(1, atoi(optarg)));
                    break;

                case 'f':
                    log_message(-1, optarg);
                    break;

                case 'z':
                    pidfile = strdup(optarg);
                    break;

                case '?':
                    return 1;
            }
        }
    }

    // normalize and check parameters
    retries ++;
    port    = (!port ? strdup(PDHCP_DEFAULT_SERVER_PORT) : port);
    address = (!address ? strdup(PDHCP_DEFAULT_ADDRESS) : address);
    pidfile = (backend ? (pidfile ? pidfile : strdup(PDHCP_DEFAULT_PIDFILE)) : pidfile);
    if (!backend && !interface)
    {
        log_message(LOG_CRIT, "you need to specify an interface in client mode - aborting");
        return 1;
    }

    // check for previously running instance
    if (pidfile)
    {
        FILE *handle = fopen(pidfile, "r");
        char pid[16];

        memset(pid, 0, sizeof(pid));
        if (handle && fgets(pid, sizeof(pid), handle)&& !kill(atoi(pid), 0))
        {
            log_message(LOG_CRIT, "another instance is already running (pid %d) - exiting", atoi(pid));
            return 1;
        }
        SFCLOSE(handle);
        if (!(handle = fopen(pidfile, "w")))
        {
            log_message(LOG_CRIT, "cannot open pidfile %s - exiting", pidfile);
            return 1;
        }
        fprintf(handle, "%d\n", getpid());
        SFCLOSE(handle);
    }

    // create, configure and bind service socket (regular in server mode, raw in client mode)
    {
        struct addrinfo *addrinfo;
        int             error = 0, option = 1;

        if ((error = getaddrinfo(address, port, NULL, &addrinfo)) ||
            (service = socket(backend ? AF_INET : AF_PACKET, backend ? SOCK_DGRAM : SOCK_RAW, backend ? IPPROTO_UDP : htons(ETH_P_IP))) < 0 ||
            (interface && setsockopt(service, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) < 0) ||
            setsockopt(service, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option)) < 0 ||
            setsockopt(service, SOL_SOCKET, SO_BROADCAST, &option, sizeof(option)) < 0 ||
            !set_handle_blocking(service, false) ||
            (backend && bind(service, (struct sockaddr *)addrinfo->ai_addr, sizeof(struct sockaddr_in)) < 0))
        {
            log_message(LOG_CRIT, "cannot bind service socket [%s:%s]: %s - exiting", address, port, (error == 0 || error == EAI_SYSTEM ? strerror(errno) : gai_strerror(error)));
            return 1;
        }
        freeaddrinfo(addrinfo);
    }

    // start main event loop
    {
        char message[BUFSIZ] = "";

        memset(workers, 0, sizeof(workers));
        srand48(time(NULL) + getpid());
        if (interface)
        {
            snprintf(message, sizeof(message), " on interface %s", interface);
        }
        if (backend || verbose)
        {
            log_message(LOG_INFO, "starting pdhcp v%s in %s mode%s", PDHCP_VERSION, backend ? "server" : "client", message);
        }
        loop = ev_loop_new(0);
        ev_io_init(&service_watcher, service_handler, service, EV_READ);
        ev_io_start(loop, &service_watcher);
        ev_timer_init(&tick_watcher, tick_handler, 0.0, 1.0);
        ev_timer_start(loop, &tick_watcher);
        ev_loop(loop, 0);
    }

    return 0;
}
