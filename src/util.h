#ifndef __UTIL_INCLUDE
#define __UTIL_INCLUDE

// includes
#include <stdio.h>
#include <stdint.h>
#include <syslog.h>
#include <sys/types.h>

// defines
#ifndef  min
#define  min(_a, _b)  ((_a) < (_b) ? (_a) : (_b))
#endif
#ifndef  max
#define  max(_a, _b)  ((_a) > (_b) ? (_a) : (_b))
#endif

#define  SFREEZ(_p) \
    if (_p) \
    { \
        free(_p); \
        _p = NULL; \
    }
#define  SFREE(_p) \
    if (_p) \
    { \
        free(_p); \
    }

#define  SCLOSEZ(_h) \
    if (_h > 0) \
    { \
        close(_h); \
        _h = -1; \
    }
#define  SCLOSE(_h) \
    if (_h > 0) \
    { \
        close(_h); \
    }
#define  SFCLOSEZ(_h) \
    if (_h) \
    { \
        fclose(_h); \
        _h = NULL; \
    }
#define  SFCLOSE(_h) \
    if (_h) \
    { \
        fclose(_h); \
    }

// functions prototypes
bool      set_handle_blocking(int, bool);
u_char    *get_mac_address(char *, bool);
u_char    *get_ip_address(char *, bool);
pid_t     exec_command(char *, char *, char *, int *, int *, int *);
void      log_message(char, const char *, ...);
uint16_t  compute_crc16(uint8_t *, int);

#endif
