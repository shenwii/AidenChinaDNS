#include <string.h>
#include <stdlib.h>

#include "iconf.h"
#include "log.h"

static char *__ckey(__const__ char *secname, __const__ char *prop)
{
    static char key[1024];
    char *tmp = key;
    while(*secname)
        *tmp++ = *secname++;
    *tmp++ = ':';
    while(*prop)
        *tmp++ = *prop++;
    *tmp = '\0';
    return key;
}

int conf_parse(conf_t *conf, __const__ char *filepath, __const__ char *secname)
{
    dictionary *ini;
    ini = iniparser_load(filepath);
    if(ini == NULL)
    {
        LOG_ERR("can not open file %s\n", filepath);
        return 1;
    }
    strcpy(conf->baddr, iniparser_getstring(ini, __ckey(secname, "bind_addr"), CONF_DEFAULT_BIND_IPV4));
    strcpy(conf->baddr6, iniparser_getstring(ini, __ckey(secname, "bind_addr6"), CONF_DEFAULT_BIND_IPV6));
    conf->bport = (uint16_t) iniparser_getint(ini, __ckey(secname, "bind_port"), CONF_DEFAULT_PORT);
    strcpy(conf->cdns, iniparser_getstring(ini, __ckey(secname, "china_dns"), CONF_DEFAULT_CHINA_DNS));
    strcpy(conf->tdns, iniparser_getstring(ini, __ckey(secname, "trustable_dns"), CONF_DEFAULT_TRUST_DNS));
    strcpy(conf->iplist, iniparser_getstring(ini, __ckey(secname, "ip_list_file"), CONF_EMPTY_STRING));
    conf->mode = iniparser_getint(ini, __ckey(secname, "mode"), 1);
    iniparser_freedict(ini);
    return 0;
}
