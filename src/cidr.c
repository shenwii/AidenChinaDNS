#include "cidr.h"
#include "log.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

static int __parse_cidr_str(char *cidr_str, unsigned short *sa_family, uint32_t *ip_arr)
{
    uint32_t *ips;
    int slen = strlen(cidr_str);
    char type = 0;
    char *s = cidr_str;
    char c;
    int pos = -1;
    while(slen--)
    {
        c = *s++;
        if(c == '.')
            type = 1;
        else if(c == ':')
            type = 2;
        else if(c == '/')
            pos = slen;
    }
    if(type == 0)
        return 1;
    slen = strlen(cidr_str);
    if(type == 1)
    {
        struct in_addr s;
        *sa_family = AF_INET;
        if(pos == -1)
        {
            if(inet_pton(AF_INET, cidr_str, &s) < 0)
                return 2;
            ips = (uint32_t *) &s;
            *ips = ntohl(*ips);
            ip_arr[0] = *ips;
            ip_arr[4] = *ips;
        }
        else
        {
            char ip_str[20];
            char m_str[10];
            memcpy(ip_str, cidr_str, slen - pos - 1);
            ip_str[slen - pos - 1] = '\0';
            memcpy(m_str, cidr_str + slen - pos, pos);
            m_str[pos] = '\0';
            errno = 0;
            int m = (int) atol(m_str);
            if(errno != 0)
                return 4;
            if(m <= 0 || m > 32)
                return 5;
            if(inet_pton(AF_INET, ip_str, &s) < 0)
                return 2;
            ips = (uint32_t *) &s;
            *ips = ntohl(*ips);
            ip_arr[0] = *ips & (0xFFFFFFFF >> (32 - m) << (32 - m));
            if(m == 32)
                ip_arr[4] = *ips;
            else
                ip_arr[4] = *ips | (0xFFFFFFFF << m >> m);
        }
    }
    else
    {
        struct in6_addr s;
        *sa_family = AF_INET6;
        if(pos == -1)
        {
            if(inet_pton(AF_INET6, cidr_str, &s) < 0)
                return 2;
            ips = (uint32_t *) &s;
            ip_arr[0] = ntohl(ips[0]);
            ip_arr[1] = ntohl(ips[1]);
            ip_arr[2] = ntohl(ips[2]);
            ip_arr[3] = ntohl(ips[3]);
            ip_arr[4] = ntohl(ips[0]);
            ip_arr[5] = ntohl(ips[1]);
            ip_arr[6] = ntohl(ips[2]);
            ip_arr[7] = ntohl(ips[3]);
        }
        else
        {
            char ip_str[60];
            char m_str[10];
            memcpy(ip_str, cidr_str, slen - pos - 1);
            ip_str[slen - pos - 1] = '\0';
            memcpy(m_str, cidr_str + slen - pos, pos);
            m_str[pos] = '\0';
            errno = 0;
            int m = (int) atol(m_str);
            if(errno != 0)
                return 4;
            if(m <= 0 || m > 128)
                return 5;
            if(inet_pton(AF_INET6, ip_str, &s) < 0)
                return 2;
            ips = (uint32_t *) &s;
            if(m <= 32)
            {
                ip_arr[0] = ntohl(ips[0]) & (0xFFFFFFFF >> (32 - m) << (32 - m));
                ip_arr[1] = 0x00000000;
                ip_arr[2] = 0x00000000;
                ip_arr[3] = 0x00000000;
                if(m == 32)
                    ip_arr[4] = ntohl(ips[0]);
                else
                    ip_arr[4] = ntohl(ips[0]) | (0xFFFFFFFF << m >> m);
                ip_arr[5] = 0xFFFFFFFF;
                ip_arr[6] = 0xFFFFFFFF;
                ip_arr[7] = 0xFFFFFFFF;
            }
            else if (m <= 64)
            {
                ip_arr[0] = ntohl(ips[0]);
                ip_arr[1] = ntohl(ips[1]) & (0xFFFFFFFF >> (64 - m) << (64 - m));
                ip_arr[2] = 0x00000000;
                ip_arr[3] = 0x00000000;
                ip_arr[4] = ntohl(ips[0]);
                if(m == 64)
                    ip_arr[5] = ntohl(ips[1]);
                else
                    ip_arr[5] = ntohl(ips[1]) | (0xFFFFFFFF << (m - 32) >> (m - 32));
                ip_arr[6] = 0xFFFFFFFF;
                ip_arr[7] = 0xFFFFFFFF;
            }
            else if (m <= 96)
            {
                ip_arr[0] = ntohl(ips[0]);
                ip_arr[1] = ntohl(ips[1]);
                ip_arr[2] = ntohl(ips[2]) & (0xFFFFFFFF >> (96 - m) << (96 - m));
                ip_arr[3] = 0x00000000;
                ip_arr[4] = ntohl(ips[0]);
                ip_arr[5] = ntohl(ips[1]);
                if(m == 96)
                    ip_arr[6] = ntohl(ips[2]);
                else
                    ip_arr[6] = ntohl(ips[2]) | (0xFFFFFFFF << (m - 64) >> (m - 64));
                ip_arr[7] = 0xFFFFFFFF;
            }
            else
            {
                ip_arr[0] = ntohl(ips[0]);
                ip_arr[1] = ntohl(ips[1]);
                ip_arr[2] = ntohl(ips[2]);
                ip_arr[3] = ntohl(ips[3]) & (0xFFFFFFFF >> (128 - m) << (128 - m));
                ip_arr[4] = ntohl(ips[0]);
                ip_arr[5] = ntohl(ips[1]);
                ip_arr[6] = ntohl(ips[2]);
                if(m == 128)
                    ip_arr[7] = ntohl(ips[3]);
                else
                    ip_arr[7] = ntohl(ips[3]) | (0xFFFFFFFF << (m - 96) >> (m - 96));
            }
        }
    }
    return 0;
}

static int __insert_cidr4(cidr_t *cidr, uint32_t sip, uint32_t eip)
{
    int rc;
    char *err_msg;
    char buf[80];
    char *sql = "insert into cidr4 (sip, eip) values (%u, %u);";
    sprintf(buf, sql, sip, eip);
    rc = sqlite3_exec(cidr, buf, NULL, NULL, &err_msg);
    if(rc != SQLITE_OK)
    {
        LOG_ERR(MSG_SQLITE_TABLE_CREATE);
        sqlite3_free(err_msg);
        return 1;
    }
    return 0;
}

static int __insert_cidr6(cidr_t *cidr
                        , uint32_t sip1
                        , uint32_t sip2
                        , uint32_t sip3
                        , uint32_t sip4
                        , uint32_t eip1
                        , uint32_t eip2
                        , uint32_t eip3
                        , uint32_t eip4)
{
    int rc;
    char *err_msg;
    char buf[200];
    char *sql = "insert into cidr6 (sip1, sip2, sip3, sip4, eip1, eip2, eip3, eip4) values (%u, %u, %u, %u, %u, %u, %u, %u);";
    sprintf(buf, sql, sip1, sip2, sip3, sip4, eip1, eip2, eip3, eip4);
    rc = sqlite3_exec(cidr, buf, NULL, NULL, &err_msg);
    if(rc != SQLITE_OK)
    {
        LOG_ERR(MSG_SQLITE_TABLE_CREATE);
        sqlite3_free(err_msg);
        return 1;
    }
    return 0;
}

static int __select_cb(void *exists, int argc, char **argv, char **col_name)
{
    *((bool *) exists) = true;
    return 0;
}

cidr_t *cidr_init()
{
    int rc;
    char *err_msg;
    cidr_t *cidr;
    char *csql1 = "create table cidr4 (" \
        "id integer primary key autoincrement," \
        "sip integer," \
        "eip integer" \
        ");";
    char *idxsql1 = "create index cidr4_idx1 on cidr4 (sip, eip);";
    char *csql2 = "create table cidr6 (" \
        "id integer primary key autoincrement," \
        "sip1 integer," \
        "sip2 integer," \
        "sip3 integer," \
        "sip4 integer," \
        "eip1 integer," \
        "eip2 integer," \
        "eip3 integer," \
        "eip4 integer" \
        ");";
    char *idxsql2 = "create index cidr6_idx1 on cidr6 (sip1, sip2, sip3, sip4, eip1, eip2, eip3, eip4);";
    rc = sqlite3_open(":memory:", &cidr);
    if(rc != SQLITE_OK)
    {
        LOG_ERR(MSG_SQLITE_OPEN);
        abort();
    }
    rc = sqlite3_exec(cidr, csql1, NULL, NULL, &err_msg);
    if(rc != SQLITE_OK)
    {
        LOG_ERR(MSG_SQLITE_TABLE_CREATE);
        sqlite3_free(err_msg);
        abort();
    }
    rc = sqlite3_exec(cidr, idxsql1, NULL, NULL, &err_msg);
    if(rc != SQLITE_OK)
    {
        LOG_ERR(MSG_SQLITE_INDEX_CREATE);
        sqlite3_free(err_msg);
        abort();
    }
    rc = sqlite3_exec(cidr, csql2, NULL, NULL, &err_msg);
    if(rc != SQLITE_OK)
    {
        LOG_ERR(MSG_SQLITE_TABLE_CREATE);
        sqlite3_free(err_msg);
        abort();
    }
    rc = sqlite3_exec(cidr, idxsql2, NULL, NULL, &err_msg);
    if(rc != SQLITE_OK)
    {
        LOG_ERR(MSG_SQLITE_INDEX_CREATE);
        sqlite3_free(err_msg);
        abort();
    }
    return cidr;
}

int cidr_append(cidr_t *cidr, char *cidr_str)
{
    unsigned short sa_family;
    uint32_t ip_arr[8] = {0};
    if(__parse_cidr_str(cidr_str, &sa_family, (uint32_t *) ip_arr) != 0)
        return 1;
    if(sa_family == AF_INET)
        return __insert_cidr4(cidr, ip_arr[0], ip_arr[4]);
    else
        return __insert_cidr6(cidr, ip_arr[0], ip_arr[1], ip_arr[2], ip_arr[3], ip_arr[4], ip_arr[5], ip_arr[6], ip_arr[7]);
}

bool cidr_match(cidr_t *cidr, struct sockaddr *addr)
{
    uint32_t *ips;
    bool exists = false;
    int rc;
    char *err_msg;
    if(addr->sa_family == AF_INET)
    {
        char buf[100];
        char *sql = "select 1 as col from cidr4 where %u >= sip and %u <= eip;";
        struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
        ips = (uint32_t *) &addr4->sin_addr;
        sprintf(buf, sql, ntohl(*ips), ntohl(*ips));
        rc = sqlite3_exec(cidr, buf, __select_cb, (void*) &exists, &err_msg);
        if(rc != SQLITE_OK)
            sqlite3_free(err_msg);
    }
    else
    {
        char buf[300];
        char *sql = "select 1 as col from cidr6 where %u >= sip1 and %u <= eip1 and %u >= sip2 and %u <= eip2 and %u >= sip3 and %u <= eip3 and %u >= sip4 and %u <= eip4;";
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
        ips = (uint32_t *) &addr6->sin6_addr;
        sprintf(buf, sql, ntohl(ips[0]), ntohl(ips[0]), ntohl(ips[1]), ntohl(ips[1]), ntohl(ips[2]), ntohl(ips[2]), ntohl(ips[3]), ntohl(ips[3]));
        rc = sqlite3_exec(cidr, buf, __select_cb, (void*) &exists, &err_msg);
        if(rc != SQLITE_OK)
            sqlite3_free(err_msg);
    }
    return exists;
}

int cidr_free(cidr_t *cidr)
{
    sqlite3_close(cidr);
    return 0;
}
