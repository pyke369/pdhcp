// mandatory includes
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#define  SYSLOG_NAMES  1
#include <util.h>

// change processus running user/group
static bool morph_processus(char *user, char *group)
{
    struct group  *group_entry;
    struct passwd *user_entry;

    if (!geteuid())
    {
        if (group && (!(group_entry = getgrnam(group)) || setgid(group_entry->gr_gid) < 0))
        {
            return false;
        }
        if (user && (!(user_entry = getpwnam(user)) || setuid(user_entry->pw_uid) < 0))
        {
            return false;
        }
    }
    return true;
}

// set/unset blocking on given handle
bool set_handle_blocking(int handle, bool value)
{
    int flag = value ? 0 : 1;

    return !ioctl(handle, FIONBIO, &flag);
}

// get interface MAC address
u_char *get_mac_address(char *interface, bool raw)
{
    struct ifreq  ifrequest;
    int           handle = -1;
    static u_char address[18];

    memset(address, 0, sizeof(address));
    if (!raw) strcpy((char *)address, "00:00:00:00:00:00");
    ifrequest.ifr_addr.sa_family = AF_INET;
    strncpy(ifrequest.ifr_name, interface, IFNAMSIZ - 1);
    if ((handle = socket(AF_INET, SOCK_DGRAM, 0)) >= 0 && !ioctl(handle, SIOCGIFHWADDR, &ifrequest))
    {
        if (raw)
        {
            memcpy(address, ifrequest.ifr_hwaddr.sa_data, ETH_ALEN);
        }
        else
        {
            sprintf((char *)address, "%02x:%02x:%02x:%02x:%02x:%02x",
                    (uint8_t)ifrequest.ifr_hwaddr.sa_data[0], (uint8_t)ifrequest.ifr_hwaddr.sa_data[1], (uint8_t)ifrequest.ifr_hwaddr.sa_data[2],
                    (uint8_t)ifrequest.ifr_hwaddr.sa_data[3], (uint8_t)ifrequest.ifr_hwaddr.sa_data[4], (uint8_t)ifrequest.ifr_hwaddr.sa_data[5]);
        }
    }
    SCLOSE(handle);
    return address;
}

// get interface IP address
u_char *get_ip_address(char *interface, bool raw)
{
    struct ifreq  ifrequest;
    int           handle = -1;
    static u_char address[16];

    memset(address, 0, sizeof(address));
    if (!raw) strcpy((char *)address, "0.0.0.0");
    ifrequest.ifr_addr.sa_family = AF_INET;
    strncpy(ifrequest.ifr_name, interface, IFNAMSIZ - 1);
    if ((handle = socket(AF_INET, SOCK_STREAM, 0)) >= 0 && !ioctl(handle, SIOCGIFADDR, &ifrequest))
    {
        if (raw)
        {
            memcpy(address, &((struct sockaddr_in *)&ifrequest.ifr_addr)->sin_addr, sizeof(uint32_t));
        }
        else
        {
            sprintf((char *)address, "%s", inet_ntoa(((struct sockaddr_in *)&ifrequest.ifr_addr)->sin_addr));
        }
    }
    SCLOSE(handle);
    return address;
}

// execute external command and capture standard streams
pid_t exec_command(char *command, char *user, char *group, int *in, int *out, int *err)
{
    struct rlimit limit;
    char   line[BUFSIZ], *argv[64];
    int    channels[3][2], handle, max = 1024, argc = 0;
    pid_t  pid;

    memset(channels, 0, sizeof(channels));
    if ((!in || !pipe(channels[0])) && (!out || !pipe(channels[1])) && (!err || !pipe(channels[2])))
    {
        if (!(pid = fork()))
        {
            if (morph_processus(user, group) && (!in || dup2(channels[0][0], 0) >= 0) && (!out || dup2(channels[1][1], 1) >= 0) && (!err || dup2(channels[2][1], 2) >= 0))
            {
                if (in)  SCLOSEZ(channels[0][1]);
                if (out) SCLOSEZ(channels[1][0]);
                if (err) SCLOSEZ(channels[2][0]);
                if (!getrlimit(RLIMIT_NOFILE, &limit))
                {
                    max = limit.rlim_cur;
                }
                for (handle = 3; handle < max; handle ++)
                {
                    SCLOSE(handle);
                }
                snprintf(line, sizeof(line) - 1, "%s", command);
                memset(argv, 0, sizeof(argv));
                while (argc < 64 && (argv[argc] = strtok(argc ? NULL : line, " \t")) != NULL)
                {
                    argc ++;
                }
                execvp(argv[0], argv);
            }
            sleep(1);
            return 1;
        }
        else if (pid > 0)
        {
            if (in)  { SCLOSEZ(channels[0][0]); set_handle_blocking(channels[0][1], false); *in  = channels[0][1]; }
            if (out) { SCLOSEZ(channels[1][1]); set_handle_blocking(channels[1][0], false); *out = channels[1][0]; }
            if (err) { SCLOSEZ(channels[2][1]); set_handle_blocking(channels[2][0], false); *err = channels[2][0]; }
            return pid;
        }
    }
    SCLOSEZ(channels[0][0]); SCLOSEZ(channels[0][1]);
    SCLOSEZ(channels[1][0]); SCLOSEZ(channels[1][1]);
    SCLOSEZ(channels[2][0]); SCLOSEZ(channels[2][1]);
    return 0;
}

// log message to both syslog and stderr
static bool _syslog_initialized = false;
static char _syslog_facility    = LOG_DAEMON;
void log_message(char level, const char *format, ...)
{
    va_list arguments;
    char    message[BUFSIZ], type[8], mark[16], unmark[8] = "\x1b[0m";
    int     index;

    if (level < 0 && !_syslog_initialized)
    {
        index = 0;
        while (facilitynames[index].c_name)
        {
            if (!strcasecmp(format, facilitynames[index].c_name))
            {
                _syslog_facility = facilitynames[index].c_val;
                break;
            }
            index ++;
        }
        return;
    }
    if (!_syslog_initialized)
    {
        openlog("pdhcp", LOG_PID, _syslog_facility);
        _syslog_initialized = true;
    }
    if (level != LOG_CRIT && level != LOG_ERR && level != LOG_WARNING && level != LOG_INFO)
    {
        level = LOG_INFO;
    }
    va_start(arguments, format);
    vsnprintf(message, sizeof(message), format, arguments);
    syslog(_syslog_facility | level, "%s", message);
    switch (level)
    {
        case LOG_CRIT:    strcpy(type, "[CRIT] "); strcpy(mark, "\x1b[1;31;47m"); break;
        case LOG_ERR:     strcpy(type, "[ERR]  "); strcpy(mark, "\x1b[1;31m"); break;
        case LOG_WARNING: strcpy(type, "[WARN] "); strcpy(mark, "\x1b[0;33m"); break;
        case LOG_INFO:    strcpy(type, "[INFO] "); strcpy(mark, "\x1b[0;36m"); break;
    }
    fprintf(stderr, "%s%s%s%s\n", mark, type, message, unmark);
}

// IETF crc16
uint16_t compute_crc16(uint8_t *data, int len)
{
    uint32_t sum = 0;
    uint16_t *word = (uint16_t *)data;

    while (len > 1)
    {
        sum += *word ++;
        if (sum & 0x80000000) sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }
    if (len) sum += (uint16_t)*((uint8_t *)word);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return ~sum;
}
