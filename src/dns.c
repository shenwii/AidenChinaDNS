#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>

#include "ascore.h"
#include "dnsprot.h"
#include "common.h"
#include "iconf.h"
#include "log.h"
#include "cidr.h"

struct sockaddr **china_dns_list;
struct sockaddr **trustable_dns_list;
size_t all_dns_cnt;
cidr_t *cidr;
conf_t conf;

typedef struct __client_data_s __client_data_t;

typedef struct __remote_data_s __remote_data_t;

typedef struct
{
    as_socket_t *sck;
    /**
     * 0: inited
     * 1: connected
     * 2: closed
     **/
    char status;
    char on_send;
} __sck_sts_t;


struct __client_data_s
{
    __sck_sts_t sck_sts;
    __remote_data_t *remote_datas;
    as_socket_t *first;
    int remote_count;
    unsigned char **buf_arr;
    size_t *buf_len_arr;
    size_t arr_len;
};

struct __remote_data_s
{
    __sck_sts_t sck_sts;
    __client_data_t *client_data;
    /**
     * 1: china dns
     * 2: trustable dns
     **/
    int type;
    size_t read_pos;
};

static struct sockaddr** __parse_address_list(char *address_list_str, size_t *cnt);

static struct sockaddr* __parse_address(char *address_str);

static int __parse_list_files(char *files_str);

static int __parse_list_file(char *file_str);

static int __free_client_data(__client_data_t *client_data);

static int __client_destroy(as_socket_t *sck);

static int __remote_udp_destroy(as_socket_t *sck);

static int __remote_tcp_destroy(as_socket_t *sck);

static int __tcp_client_on_accepted(as_tcp_t *srv, as_tcp_t *clnt, void **data, as_socket_destroying_f *cb);

static int __tcp_remote_on_connected(as_tcp_t *remote, char status);

static int __tcp_remote_writing(as_tcp_t *remote);

static int __tcp_remote_on_wrote(as_tcp_t *remote, __const__ unsigned char *buf, __const__ size_t len);

static int __tcp_remote_on_read(as_tcp_t *remote, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len);

static int __tcp_client_on_read(as_tcp_t *clnt, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len);

static int __udp_client_on_connect(as_udp_t *srv, as_udp_t *clnt, void **data, as_socket_destroying_f *cb);

static int __udp_client_on_read(as_udp_t *clnt, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len);

static int __udp_remote_on_wrote(as_udp_t *remote, __const__ unsigned char *buf, __const__ size_t len);

static int __udp_remote_on_read(as_udp_t *remote, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len);

static int __usage(char *prog)
{
    printf("Usage: %s INI_FILE\n", prog);
    fflush(stdout);
    return 1;
}

int main(int argc, char **argv)
{
    as_loop_t *loop;
    as_tcp_t *tcp;
    as_udp_t *udp;
    struct sockaddr_in6 addr6;
    struct sockaddr_in addr;
    if(argc < 2)
        return __usage(argv[0]);
    if(conf_parse(&conf, argv[1], "ChinaDns") != 0)
    {
        LOG_ERR(MSG_PARSE_INI_FILE);
        return 1;
    }
    if(conf.mode != 1 && conf.mode != 2)
    {
        LOG_ERR(MSG_PARAM_MODE);
        return 1;
    }
    if(strcmp(conf.iplist, CONF_EMPTY_STRING) == 0)
    {
        LOG_ERR(MSG_PARAM_IP_LIST);
        return 1;
    }
    all_dns_cnt = 0;
    china_dns_list = __parse_address_list(conf.cdns, &all_dns_cnt);
    trustable_dns_list = __parse_address_list(conf.tdns, &all_dns_cnt);
    cidr = cidr_init();
    if(__parse_list_files(conf.iplist) != 0)
    {
        cidr_free(cidr);
        return 1;
    }
    loop = as_loop_init();
    if(getipv6hostbyname(conf.baddr6, &addr6) != 0)
    {
        LOG_ERR(MSG_RESOLV_HOST, conf.baddr6);
        cidr_free(cidr);
        return 1;
    }
    addr6.sin6_port = htons(conf.bport);
    if(getipv4hostbyname(conf.baddr, &addr) != 0)
    {
        LOG_ERR(MSG_RESOLV_HOST, conf.baddr);
        cidr_free(cidr);
        return 1;
    }
    addr.sin_port = htons(conf.bport);

    //bind ipv6 tcp address
    tcp = as_tcp_init(loop, NULL, NULL);
    if(as_tcp_bind(tcp, (struct sockaddr *) &addr6, AS_TCP_IPV6ONLY) != 0)
    {
        LOG_ERR(MSG_TCP_BIND, conf.baddr6, conf.bport);
        cidr_free(cidr);
        return 1;
    }
    if(as_tcp_listen(tcp, __tcp_client_on_accepted) != 0)
    {
        LOG_ERR(MSG_TCP_LISTENED);
        cidr_free(cidr);
        return 1;
    }
    LOG_INFO(MSG_TCP_LISTEN_ON, conf.baddr6, conf.bport);

    //bind ipv4 tcp address
    tcp = as_tcp_init(loop, NULL, NULL);
    if(as_tcp_bind(tcp, (struct sockaddr *) &addr, 0) != 0)
    {
        LOG_ERR(MSG_TCP_BIND, conf.baddr, conf.bport);
        cidr_free(cidr);
        return 1;
    }
    if(as_tcp_listen(tcp, __tcp_client_on_accepted) != 0)
    {
        LOG_ERR(MSG_TCP_LISTENED);
        cidr_free(cidr);
        return 1;
    }
    LOG_INFO(MSG_TCP_LISTEN_ON, conf.baddr, conf.bport);

    //bind ipv6 udp address
    udp = as_udp_init(loop, NULL, NULL);
    if(as_udp_bind(udp, (struct sockaddr *) &addr6, AS_UDP_IPV6ONLY) != 0)
    {
        LOG_ERR(MSG_UDP_BIND, conf.baddr6, conf.bport);
        cidr_free(cidr);
        return 1;
    }
    if(as_udp_listen(udp, __udp_client_on_connect) != 0)
    {
        LOG_ERR(MSG_UDP_LISTENED);
        cidr_free(cidr);
        return 1;
    }
    LOG_INFO(MSG_UDP_LISTEN_ON, conf.baddr6, conf.bport);

    //bind ipv4 udp address
    udp = as_udp_init(loop, NULL, NULL);
    if(as_udp_bind(udp, (struct sockaddr *) &addr, 0) != 0)
    {
        LOG_ERR(MSG_UDP_BIND, conf.baddr, conf.bport);
        cidr_free(cidr);
        return 1;
    }
    if(as_udp_listen(udp, __udp_client_on_connect) != 0)
    {
        LOG_ERR(MSG_UDP_LISTENED);
        cidr_free(cidr);
        return 1;
    }
    LOG_INFO(MSG_UDP_LISTEN_ON, conf.baddr, conf.bport);
    as_loop_run(loop);
    return 0;
}

static struct sockaddr** __parse_address_list(char *address_list_str, size_t *cnt)
{
    int len = 1;
    struct sockaddr **addr_list = (struct sockaddr **) malloc(sizeof(struct sockaddr *) * len);
    if(addr_list == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    addr_list[len - 1] = NULL;
    struct sockaddr *addr;
    char addr_str[100];
    int addrsl = strlen(address_list_str);
    int pos = 0;
    char *s = address_list_str;
    while(addrsl--)
    {
        if(*address_list_str++ == ',')
        {
            if(pos > 0)
            {
                memcpy(addr_str, s, pos);
                addr_str[pos] = '\0';
                addr = __parse_address(addr_str);
                if(addr != NULL)
                {
                    addr_list = (struct sockaddr **) realloc(addr_list, sizeof(struct sockaddr *) * ++len);
                    if(addr_list == NULL)
                    {
                        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
                        abort();
                    }
                    addr_list[len - 2] = addr;
                    addr_list[len - 1] = NULL;
                }
            }
            s = address_list_str;
            pos = -1;
        }
        pos++;
    }
    if(pos > 0)
    {
        memcpy(addr_str, s, pos);
        addr_str[pos] = '\0';
        addr = __parse_address(addr_str);
        if(addr != NULL)
        {
            addr_list = (struct sockaddr **) realloc(addr_list, sizeof(struct sockaddr *) * ++len);
            if(addr_list == NULL)
            {
                LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
                abort();
            }
            addr_list[len - 2] = addr;
            addr_list[len - 1] = NULL;
        }
    }
    *cnt += len - 1;
    return addr_list;
}

static struct sockaddr* __parse_address(char *address_str)
{
    char addr_str[100];
    char port_str[10];
    uint16_t port = 53;
    int addrsl = strlen(address_str);
    int pos = addrsl;
    struct sockaddr *addr;
    if(address_str[addrsl - 1] != ']')
        for(int i = 0; i < addrsl; i++)
            if(address_str[i] == ':') pos = i;
    if(address_str[0] == '[' && address_str[pos - 1] == ']')
    {
        memcpy(addr_str, address_str + 1, pos - 2);
        addr_str[pos - 2] = '\0';
    }
    else
    {
        memcpy(addr_str, address_str, pos);
        addr_str[pos] = '\0';
    }
    if(pos < addrsl - 1 && addrsl - pos - 1 < 10)
    {
        memcpy(port_str, address_str + pos + 1, addrsl - pos - 1);
        port_str[addrsl - pos - 1] = '\0';
        errno = 0;
        port = (uint16_t) atol(port_str);
        if(errno != 0)
        {
            LOG_WARN(MSG_RESOLV_HOST, address_str);
            return NULL;
        }
    }
    addr = (struct sockaddr *) malloc(sizeof(struct sockaddr_storage));
    if(addr == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    if(getfirsthostbyname(addr_str, addr) != 0)
    {
        LOG_WARN(MSG_RESOLV_HOST, address_str);
        free(addr);
        return NULL;
    }
    if(addr->sa_family == AF_INET)
    {
        struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
        addr4->sin_port = htons(port);
    }
    else
    {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
        addr6->sin6_port = htons(port);
    }
    return addr;
}

static int __parse_list_files(char *files_str)
{
    int slen = strlen(files_str);
    char *s = files_str;
    char filename[256];
    int c = 0;
    while(slen--)
    {
        if(*files_str++ == ',')
        {
            if(c > 0)
            {
                memcpy(filename, s, c);
                filename[c] = '\0';
                if(__parse_list_file(filename) != 0)
                    return 1;
            }
            s = files_str;
            c = -1;
        }
        c++;
    }
    if(c > 0)
    {
        memcpy(filename, s, c);
        filename[c] = '\0';
        if(__parse_list_file(filename) != 0)
            return 1;
    }
    return 0;
}

static int __parse_list_file(char *file_str)
{
    FILE *fp;
    errno = 0;
    fp = fopen(file_str, "r");
    char line[255];
    char *line_tmp = line;
    int c;
    int cnt = 0;
    if(errno != 0)
    {
        LOG_ERR(MSG_OPEN_FILE, file_str);
        return 1;
    }
    while((c = fgetc(fp)) != EOF)
    {
        if(c == '\n')
        {
            if(cnt > 0 && line[0] != '#')
            {
                line[cnt] = '\0';
                if(cidr_append(cidr, (char *) line) != 0)
                    LOG_WARN(MSG_ILLEGAL_CIDR, (char *) line);
            }
            cnt = 0;
            line_tmp = line;
            continue;
        }
        if(c == '\r')
            continue;
        if(cnt == 0 && (c == ' ' || c == '\t' || c == '\f' || c == '\v'))
            continue;
        *line_tmp++ = c;
        cnt++;
    }
    if(cnt > 0 && line[0] != '#')
    {
        line[cnt] = '\0';
        if(cidr_append(cidr, (char *) line) != 0)
            LOG_WARN(MSG_ILLEGAL_CIDR, (char *) line);
    }
    fclose(fp);
    return 0;
}

static int __free_client_data(__client_data_t *client_data)
{
    unsigned char **buf_arr;
    if(client_data->arr_len != 0)
    {
        buf_arr = client_data->buf_arr;
        while(client_data->arr_len--)
            free(*buf_arr++);
        free(client_data->buf_len_arr);
        free(client_data->buf_arr);
    }
    free(client_data->remote_datas);
    if(client_data->sck_sts.status == 2)
        free(client_data);
    return 0;
}

static int __client_destroy(as_socket_t *sck)
{
    size_t cnt = all_dns_cnt;
    __client_data_t *client_data = (__client_data_t *) as_socket_data(sck);
    client_data->sck_sts.status = 2;
    if(client_data->remote_count == 0)
    {
        free(client_data);
    }
    else
    {
        __remote_data_t *remote_datas = client_data->remote_datas;
        __remote_data_t *remote_data;
        while(cnt--)
        {
            remote_data = remote_datas++;
            if(remote_data->sck_sts.status != 2)
            {
                as_close(remote_data->sck_sts.sck);
            }
        }
    }
    return 0;
}

static int __remote_udp_destroy(as_socket_t *sck)
{
    __remote_data_t *remote_data = (__remote_data_t *) as_socket_data(sck);
    __client_data_t *client_data = remote_data->client_data;
    remote_data->sck_sts.status = 2;
    client_data->remote_count--;
    if(client_data->remote_count == 0)
        return __free_client_data(client_data);
    return 0;
}

static int __remote_tcp_destroy(as_socket_t *sck)
{
    __remote_data_t *remote_data = (__remote_data_t *) as_socket_data(sck);
    __client_data_t *client_data = remote_data->client_data;
    remote_data->sck_sts.status = 2;
    client_data->remote_count--;
    if(client_data->remote_count == 0)
        return __free_client_data(client_data);
    return 0;
}

static int __tcp_client_on_accepted(as_tcp_t *srv, as_tcp_t *clnt, void **data, as_socket_destroying_f *cb)
{
    char isconnected = 0;
    struct sockaddr **dns_list;
    struct sockaddr *dns_addr;
    __client_data_t *client_data = (__client_data_t *) malloc(sizeof(__client_data_t));
    if(client_data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    memset(client_data, 0, sizeof(__client_data_t));
    client_data->first = NULL;
    client_data->sck_sts.status = 1;
    client_data->sck_sts.sck = (as_socket_t *) clnt;
    client_data->remote_datas = (__remote_data_t *) calloc(all_dns_cnt, sizeof(__remote_data_t));
    if(client_data->remote_datas == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    __remote_data_t *remote_datas = client_data->remote_datas;
    dns_list = china_dns_list;
    while((dns_addr = *dns_list++) != NULL)
    {
        __remote_data_t *remote_data = remote_datas++;
        remote_data->type = 1;
        remote_data->client_data = client_data;
        as_tcp_t *remote = as_tcp_init(as_socket_loop((as_socket_t *) clnt), remote_data, __remote_tcp_destroy);
        remote_data->sck_sts.status = 0;
        remote_data->sck_sts.sck = (as_socket_t *) remote;
        client_data->remote_count++;
        if(as_tcp_connect(remote, dns_addr, __tcp_remote_on_connected) != 0)
        {
            remote_data->sck_sts.status = 2;
            as_close((as_socket_t *) remote);
            continue;
        }
        isconnected = 1;
    }
    dns_list = trustable_dns_list;
    while((dns_addr = *dns_list++) != NULL)
    {
        __remote_data_t *remote_data = remote_datas++;
        remote_data->type = 2;
        remote_data->client_data = client_data;
        as_tcp_t *remote = as_tcp_init(as_socket_loop((as_socket_t *) clnt), remote_data, __remote_tcp_destroy);
        remote_data->sck_sts.status = 0;
        remote_data->sck_sts.sck = (as_socket_t *) remote;
        client_data->remote_count++;
        if(as_tcp_connect(remote, dns_addr, __tcp_remote_on_connected) != 0)
        {
            remote_data->sck_sts.status = 2;
            as_close((as_socket_t *) remote);
            continue;
        }
        isconnected = 1;
    }
    if(isconnected == 0)
    {
        client_data->sck_sts.status = 2;
        return 1;
    }
    *data = client_data;
    *cb = __client_destroy;
    return as_tcp_read_start(clnt, __tcp_client_on_read, 0);
}

static int __tcp_remote_on_connected(as_tcp_t *remote, char status)
{
    __remote_data_t *remote_data = (__remote_data_t *) as_socket_data((as_socket_t *) remote);
    if(status != 0)
        return 1;
    remote_data->sck_sts.status = 1;
    __tcp_remote_writing(remote);
    return as_tcp_read_start(remote, __tcp_remote_on_read, AS_READ_ONESHOT);
}

static int __tcp_remote_writing(as_tcp_t *remote)
{
    __remote_data_t *remote_data = (__remote_data_t *) as_socket_data((as_socket_t *) remote);
    __client_data_t *client_data = remote_data->client_data;
    if(remote_data->read_pos < client_data->arr_len)
    {
        remote_data->sck_sts.on_send = 1;
        as_tcp_write(remote, client_data->buf_arr[remote_data->read_pos], client_data->buf_len_arr[remote_data->read_pos], __tcp_remote_on_wrote);
    }
    return 0;
}

static int __tcp_remote_on_wrote(as_tcp_t *remote, __const__ unsigned char *buf, __const__ size_t len)
{
    __remote_data_t *remote_data = (__remote_data_t *) as_socket_data((as_socket_t *) remote);
    remote_data->read_pos++;
    remote_data->sck_sts.on_send = 0;
    return __tcp_remote_writing(remote);
}

static int __tcp_remote_on_read(as_tcp_t *remote, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len)
{
    char can_send = 0;
    char is_find = 0;
    int rcode;
    struct sockaddr_storage addr;
    __remote_data_t *remote_data = (__remote_data_t *) as_socket_data((as_socket_t *) remote);
    __client_data_t *client_data = remote_data->client_data;
    as_tcp_t *client = (as_tcp_t *) client_data->sck_sts.sck;
    if(client_data->first == NULL || client_data->first == (as_socket_t *) remote)
    {
        LOG_DEBUG("recv from: %s\n", address_str((struct sockaddr *) as_dest_addr((as_socket_t *) remote)));
        dns_prtcl_t dns_prtcl;
        rcode = dns_response_parse(buf + 2, len - 2, &dns_prtcl);
        if(rcode == 0)
        {
            for(int i = 0; i < dns_prtcl.header.an_count; i++)
            {
                if(dns_prtcl.answer[i].type == 0x01)
                {
                    struct sockaddr_in *addr_in = (struct sockaddr_in *) &addr;
                    addr_in->sin_family = AF_INET;
                    memcpy(&addr_in->sin_addr, dns_prtcl.answer[i].data, 4);
                    is_find = 1;
                    break;
                }
                else if(dns_prtcl.answer[i].type == 0x1c)
                {
                    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) &addr;
                    addr_in6->sin6_family = AF_INET;
                    memcpy(&addr_in6->sin6_addr, dns_prtcl.answer[i].data, 16);
                    is_find = 1;
                    break;
                }
            }
            if(is_find)
            {
                LOG_DEBUG("resolv host %s to %s\n", dns_prtcl.question[0].query, address_without_port_str((struct sockaddr *) &addr));
                if(cidr_match(cidr, (struct sockaddr *) &addr))
                {
                    if(conf.mode == 1 && remote_data->type == 1)
                        can_send = 1;
                    if(conf.mode == 2 && remote_data->type == 2)
                        can_send = 1;
                }
                else
                {
                    if(conf.mode == 1 && remote_data->type == 2)
                        can_send = 1;
                    if(conf.mode == 2 && remote_data->type == 1)
                        can_send = 1;
                }
            }
            else
            {
                if(remote_data->type == 2)
                    can_send = 1;
            }
            dns_prtcl_free(&dns_prtcl);
        }
        else
        {
            LOG_ERR("resolv failed\n");
        }
    }
    if(can_send == 1)
    {
        LOG_DEBUG("send response\n");
        if(is_find)
        {
            LOG_INFO("query dns success, matched dns server: %s, ip = %s\n", address_str((struct sockaddr *) as_dest_addr((as_socket_t *) remote)), address_without_port_str((struct sockaddr *) &addr));
        }
        else
        {
            LOG_INFO("query dns failed, matched dns server: %s\n", address_str((struct sockaddr *) as_dest_addr((as_socket_t *) remote)));
        }
        client_data->first = (as_socket_t *) remote;
        as_tcp_write(client, buf, len, NULL);
    }
    return 0;
}

static int __tcp_client_on_read(as_tcp_t *clnt, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len)
{
    __client_data_t *client_data = (__client_data_t *) as_socket_data((as_socket_t *) clnt);
    size_t cnt = all_dns_cnt;
    __remote_data_t *remote_datas = client_data->remote_datas;
    __remote_data_t *remote_data;
    if(client_data->arr_len == 0)
    {
        client_data->buf_arr = malloc(sizeof(unsigned char *));
        client_data->buf_len_arr = malloc(sizeof(size_t));
    }
    else
    {
        client_data->buf_arr = realloc(client_data->buf_arr, sizeof(unsigned char *) * (client_data->arr_len + 1));
        client_data->buf_len_arr = realloc(client_data->buf_len_arr, sizeof(size_t) * (client_data->arr_len + 1));

    }
    if(client_data->buf_arr == NULL || client_data->buf_len_arr == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    client_data->buf_arr[client_data->arr_len] = malloc(len);
    if(client_data->buf_arr[client_data->arr_len] == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    memcpy(client_data->buf_arr[client_data->arr_len], buf, len);
    client_data->buf_len_arr[client_data->arr_len] = len;
    client_data->arr_len++;
    while(cnt--) 
    {
        remote_data = remote_datas++;
        if(remote_data->sck_sts.status == 1 && remote_data->sck_sts.on_send == 0)
        {
            __tcp_remote_writing((as_tcp_t *) remote_data->sck_sts.sck);
        }
    }
    return 0;
}

static int __udp_client_on_connect(as_udp_t *srv, as_udp_t *clnt, void **data, as_socket_destroying_f *cb)
{
    char isconnected = 0;
    struct sockaddr **dns_list;
    struct sockaddr *dns_addr;
    __client_data_t *client_data = (__client_data_t *) malloc(sizeof(__client_data_t));
    if(client_data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    memset(client_data, 0, sizeof(__client_data_t));
    client_data->first = NULL;
    client_data->sck_sts.status = 1;
    client_data->sck_sts.sck = (as_socket_t *) clnt;
    client_data->remote_datas = (__remote_data_t *) calloc(all_dns_cnt, sizeof(__remote_data_t));
    if(client_data->remote_datas == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    __remote_data_t *remote_datas = client_data->remote_datas;
    dns_list = china_dns_list;
    while((dns_addr = *dns_list++) != NULL)
    {
        __remote_data_t *remote_data = remote_datas++;
        remote_data->type = 1;
        remote_data->client_data = client_data;
        as_udp_t *remote = as_udp_init(as_socket_loop((as_socket_t *) clnt), remote_data, __remote_udp_destroy);
        remote_data->sck_sts.status = 1;
        remote_data->sck_sts.sck = (as_socket_t *) remote;
        client_data->remote_count++;
        if(as_udp_connect(remote, dns_addr) != 0)
        {
            remote_data->sck_sts.status = 2;
            as_close((as_socket_t *) remote);
            continue;
        }
        isconnected = 1;
    }
    dns_list = trustable_dns_list;
    while((dns_addr = *dns_list++) != NULL)
    {
        __remote_data_t *remote_data = remote_datas++;
        remote_data->type = 2;
        remote_data->client_data = client_data;
        as_udp_t *remote = as_udp_init(as_socket_loop((as_socket_t *) clnt), remote_data, __remote_udp_destroy);
        remote_data->sck_sts.status = 1;
        remote_data->sck_sts.sck = (as_socket_t *) remote;
        client_data->remote_count++;
        if(as_udp_connect(remote, dns_addr) != 0)
        {
            remote_data->sck_sts.status = 2;
            as_close((as_socket_t *) remote);
            continue;
        }
        isconnected = 1;
    }
    if(isconnected == 0)
    {
        client_data->sck_sts.status = 2;
        return 1;
    }
    *data = client_data;
    *cb = __client_destroy;
    return as_udp_read_start(clnt, __udp_client_on_read, 0);
}

static int __udp_client_on_read(as_udp_t *clnt, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len)
{
    int cnt = all_dns_cnt;
    __client_data_t *client_data = (__client_data_t *) as_socket_data((as_socket_t *) clnt);
    __remote_data_t *remote_datas = client_data->remote_datas;
    __remote_data_t *remote_data;
    while(cnt--)
    {
        remote_data = remote_datas++;
        if(remote_data->sck_sts.status == 1)
        {
            as_udp_write((as_udp_t *) remote_data->sck_sts.sck, buf, len, __udp_remote_on_wrote);
        }
    }
    return 0;
}

static int __udp_remote_on_wrote(as_udp_t *remote, __const__ unsigned char *buf, __const__ size_t len)
{
    return as_udp_read_start(remote, __udp_remote_on_read, AS_READ_ONESHOT);
}

static int __udp_remote_on_read(as_udp_t *remote, __const__ struct msghdr *msg, __const__ unsigned char *buf, __const__ size_t len)
{
    char can_send = 0;
    char is_find = 0;
    int rcode;
    struct sockaddr_storage addr;
    __remote_data_t *remote_data = (__remote_data_t *) as_socket_data((as_socket_t *) remote);
    __client_data_t *client_data = remote_data->client_data;
    as_udp_t *client = (as_udp_t *) client_data->sck_sts.sck;
    if(client_data->first == NULL || client_data->first == (as_socket_t *) remote)
    {
        LOG_DEBUG("recv from: %s\n", address_str((struct sockaddr *) as_dest_addr((as_socket_t *) remote)));
        dns_prtcl_t dns_prtcl;
        rcode = dns_response_parse(buf, len, &dns_prtcl);
        if(rcode == 0)
        {
            for(int i = 0; i < dns_prtcl.header.an_count; i++)
            {
                if(dns_prtcl.answer[i].type == 0x01)
                {
                    struct sockaddr_in *addr_in = (struct sockaddr_in *) &addr;
                    addr_in->sin_family = AF_INET;
                    memcpy(&addr_in->sin_addr, dns_prtcl.answer[i].data, 4);
                    is_find = 1;
                    break;
                }
                else if(dns_prtcl.answer[i].type == 0x1c)
                {
                    struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) &addr;
                    addr_in6->sin6_family = AF_INET;
                    memcpy(&addr_in6->sin6_addr, dns_prtcl.answer[i].data, 16);
                    is_find = 1;
                    break;
                }
            }
            if(is_find)
            {
                LOG_DEBUG("resolv host %s to %s\n", dns_prtcl.question[0].query, address_without_port_str((struct sockaddr *) &addr));
                if(cidr_match(cidr, (struct sockaddr *) &addr))
                {
                    if(conf.mode == 1 && remote_data->type == 1)
                        can_send = 1;
                    if(conf.mode == 2 && remote_data->type == 2)
                        can_send = 1;
                }
                else
                {
                    if(conf.mode == 1 && remote_data->type == 2)
                        can_send = 1;
                    if(conf.mode == 2 && remote_data->type == 1)
                        can_send = 1;
                }
            }
            else
            {
                if(remote_data->type == 2)
                    can_send = 1;
            }
            dns_prtcl_free(&dns_prtcl);
        }
        else
        {
            LOG_ERR("resolv failed\n");
        }
    }
    if(can_send == 1)
    {
        LOG_DEBUG("send response\n");
        if(is_find)
        {
            LOG_INFO("query dns success, matched dns server: %s, ip = %s\n", address_str((struct sockaddr *) as_dest_addr((as_socket_t *) remote)), address_without_port_str((struct sockaddr *) &addr));
        }
        else
        {
            LOG_INFO("query dns failed, matched dns server: %s\n", address_str((struct sockaddr *) as_dest_addr((as_socket_t *) remote)));
        }
        client_data->first = (as_socket_t *) remote;
        as_udp_write(client, buf, len, NULL);
    }
    return 0;
}
