#ifndef _ICONF_H
#define _ICONF_H

#define CONF_DEFAULT_PORT 53
#define CONF_DEFAULT_BIND_IPV4 "localhost"
#define CONF_DEFAULT_BIND_IPV6 "localhost"
#define CONF_DEFAULT_CHINA_DNS "114.114.114.114"
#define CONF_DEFAULT_TRUST_DNS "8.8.8.8"
#define CONF_EMPTY_STRING ""

#include <stdint.h>
#include "iniparser/iniparser.h"

typedef struct
{
    char baddr[255];
    char baddr6[255];
    uint16_t bport;
    char cdns[512];
    char tdns[512];
    char iplist[1024];
    int mode;
} conf_t;

int conf_parse(conf_t *conf, __const__ char *filepath, __const__ char *secname);

#endif
