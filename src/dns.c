#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <netinet/in.h>

#include "ascore.h"
#include "common.h"
#include "iconf.h"
#include "log.h"
#include "cidr.h"

struct sockaddr **china_dns_list;
struct sockaddr **trustable_dns_list;
cidr_t *cidr;
conf_t conf;

struct __client_data_s
{
    as_socket_t *first;
    as_socket_t **remotes;
    pthread_mutex_t lock;
    char type;
    char status;
};

struct __remote_data_s
{
    as_socket_t *client;
    struct __client_data_s *client_data;
    struct sockaddr *dns_addr;
    pthread_mutex_t lock;
    pthread_cond_t signal;
    char *buf;
    int len;
    char status;
    char type;
};

typedef struct __client_data_s __client_data_t;

typedef struct __remote_data_s __remote_data_t;

static struct sockaddr** __parse_address_list(char *address_list_str);

static struct sockaddr* __parse_address(char *address_str);

static int __parse_dns_protocol(char *buf, int len, struct sockaddr *addr, char sck_type);

static int __parse_list_files(char *files_str);

static int __parse_list_file(char *file_str);

static int __client_destroy(as_socket_t *sck);

static int __remote_udp_destroy(as_socket_t *sck);

static int __remote_tcp_destroy(as_socket_t *sck);

static int __tcp_client_on_connect(as_tcp_t *srv, as_tcp_t *clnt, void **data, as_socket_destroying_f *cb);

static void *__tcp_connect_to_remote_thread(void *param);

static int __tcp_remote_on_read(as_tcp_t *remote, __const__ char *buf, __const__ int len);

static int __tcp_client_on_read(as_tcp_t *clnt, __const__ char *buf, __const__ int len);

static int __udp_client_on_connect(as_udp_t *srv, as_udp_t *clnt, void **data, as_socket_destroying_f *cb);

static int __udp_client_on_read(as_udp_t *clnt, __const__ struct msghdr *msg, __const__ char *buf, __const__ int len);

static int __udp_remote_on_read(as_udp_t *remote, __const__ struct msghdr *msg, __const__ char *buf, __const__ int len);

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
    china_dns_list = __parse_address_list(conf.cdns);
    trustable_dns_list = __parse_address_list(conf.tdns);
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
    if(as_tcp_listen(tcp, __tcp_client_on_connect) != 0)
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
    if(as_tcp_listen(tcp, __tcp_client_on_connect) != 0)
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

static struct sockaddr** __parse_address_list(char *address_list_str)
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

static int __dns_queries_len(unsigned char *buf, int len)
{
    int tl = 0;
    unsigned char l;
    if(len == 0)
        return 0;
    if(buf[0] >> 6 == 0x03)
    {
        if(len <= 2)
            return -1;
        else
            return 2;
    }
    else
    {
        while((l = *buf) != 0)
        {
            if(len <= l + 1)
                return -1;
            tl += l + 1;
            buf += l + 1;
        }
    }
    if(len <= tl + 1)
        return -1;
    else
        return tl + 1;
}

static int __parse_dns_protocol(char *buf, int len, struct sockaddr *addr, char sck_type)
{
    int dl;
    uint16_t cnt;
    uint16_t *type;
    char *data;
    uint16_t *data_len;
    //handle header
    if(sck_type == 1)
    {
        if(len <= 2)
            return 1;
        buf += 2;
        len -= 2;
    }
    if(len <= 12)
        return 1;
    char rcode = buf[3] >> 3 & 0x0F;
    if(rcode != 0)
        return 1;
    uint16_t *quest_cnt = (uint16_t *) &buf[4];
    uint16_t *answ_cnt = (uint16_t *) &buf[6];
//     uint16_t *auth_cnt = (uint16_t *) &buf[8];
//     uint16_t *addit_cnt = (uint16_t *) &buf[10];
    //skpi header
    buf += 12;
    len -= 12;
    //handle Questions
    cnt = ntohs(*quest_cnt);
    while(cnt--)
    {
        dl = __dns_queries_len((unsigned char *) buf, len);
        if(dl == -1)
            return 2;
        if(len <= dl + 4)
            return 3;
        buf += dl + 4;
        len -= dl + 4;
    }
    //handle Answers
    cnt = ntohs(*answ_cnt);
    while(cnt--)
    {
        dl = __dns_queries_len((unsigned char *) buf, len);
        if(dl == -1)
            return 2;
        if(len <= dl + 8)
            return 4;
        buf += dl;
        len -= dl;
        type = (uint16_t *) buf;
        buf += 8;
        len -= 8;
        data_len = (uint16_t *) buf;
        data = &buf[2];
        buf += 2 + ntohs(*data_len);
        len -= 2 + ntohs(*data_len);
        if(ntohs(*type) == 0x01 && ntohs(*data_len) == 4)
        {
            //ipv4
            addr->sa_family = AF_INET;
            struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
            memcpy(&addr4->sin_addr, data, 4);
            return 0;
        }
        if(ntohs(*type) == 0x1C && ntohs(*data_len) == 16)
        {
            //ipv6
            addr->sa_family = AF_INET6;
            struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
            memcpy(&addr6->sin6_addr, data, 16);
            return 0;
        }
    }
    return -1;
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

static int __client_destroy(as_socket_t *sck)
{
    __client_data_t *client_data = (__client_data_t *) as_socket_data(sck);
    as_socket_t **remotes = client_data->remotes;
    as_socket_t *remote;
    while((remote = *remotes++) != NULL)
    {
        as_close(remote);
    }
    client_data->status = 0;
    return 0;
}

static int __remote_udp_destroy(as_socket_t *sck)
{
    char m = 0;
    __remote_data_t *remote_data = (__remote_data_t *) as_socket_data(sck);
    __client_data_t *client_data = remote_data->client_data;
    as_socket_t **remotes = client_data->remotes;
    as_socket_t *remote;
    while((remote = *remotes++) != NULL)
    {
        if(remote == sck)
            m = 1;
        if(m == 1)
            *(remotes - 1) = *remotes;
    }
    if(*client_data->remotes == NULL)
    {
        free(client_data->remotes);
        free(client_data);
    }
    free(remote_data);
    return 0;
}

static int __remote_tcp_destroy(as_socket_t *sck)
{
    char m = 0;
    __remote_data_t *remote_data = (__remote_data_t *) as_socket_data(sck);
    __client_data_t *client_data = remote_data->client_data;
    as_socket_t **remotes = client_data->remotes;
    as_socket_t *remote;
    pthread_mutex_lock(&remote_data->lock);
    remote_data->status = 2;
    pthread_cond_broadcast(&remote_data->signal);
    pthread_mutex_unlock(&remote_data->lock);
    while((remote = *remotes++) != NULL)
    {
        if(remote == sck)
            m = 1;
        if(m == 1)
            *(remotes - 1) = *remotes;
    }
    if(*client_data->remotes == NULL)
    {
        free(client_data->remotes);
        free(client_data);
    }
    return 0;
}

static int __tcp_client_on_connect(as_tcp_t *srv, as_tcp_t *clnt, void **data, as_socket_destroying_f *cb)
{
    int cnt = 0;
    struct sockaddr **dns_list;
    struct sockaddr *dns_addr;
    dns_list = china_dns_list;
    while(*dns_list++ != NULL)
        cnt++;
    dns_list = trustable_dns_list;
    while(*dns_list++ != NULL)
        cnt++;
    __client_data_t *client_data = (__client_data_t *) malloc(sizeof(__client_data_t));
    if(client_data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    client_data->first = NULL;
    client_data->remotes = (as_socket_t **) malloc(sizeof(as_socket_t *) * (cnt + 1));
    if(client_data->remotes == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    if(pthread_mutex_init(&client_data->lock, NULL) != 0)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    client_data->type = 1;
    client_data->status = 1;
    as_socket_t **remotes = client_data->remotes;
    dns_list = china_dns_list;
    while((dns_addr = *dns_list++) != NULL)
    {
        __remote_data_t *remote_data = (__remote_data_t *) malloc(sizeof(__remote_data_t));
        if(remote_data == NULL)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        remote_data->client = (as_socket_t *) clnt;
        remote_data->client_data = client_data;
        remote_data->type = 1;
        remote_data->dns_addr = dns_addr;
        remote_data->buf = NULL;
        remote_data->len = 0;
        remote_data->status = 0;
        if(pthread_mutex_init(&remote_data->lock, NULL) != 0)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        if(pthread_cond_init(&remote_data->signal, NULL) != 0)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        as_tcp_t *remote = as_tcp_init(as_socket_loop((as_socket_t *) clnt), remote_data, __remote_tcp_destroy);
        *remotes++ = (as_socket_t *) remote;
        as_thread_task((as_socket_t *) remote, __tcp_connect_to_remote_thread, remote);
    }
    dns_list = trustable_dns_list;
    while((dns_addr = *dns_list++) != NULL)
    {
        __remote_data_t *remote_data = (__remote_data_t *) malloc(sizeof(__remote_data_t));
        if(remote_data == NULL)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        remote_data->client = (as_socket_t *) clnt;
        remote_data->client_data = client_data;
        remote_data->type = 2;
        remote_data->dns_addr = dns_addr;
        remote_data->buf = NULL;
        remote_data->len = 0;
        remote_data->status = 0;
        if(pthread_mutex_init(&remote_data->lock, NULL) != 0)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        if(pthread_cond_init(&remote_data->signal, NULL) != 0)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        as_tcp_t *remote = as_tcp_init(as_socket_loop((as_socket_t *) clnt), remote_data, __remote_tcp_destroy);
        *remotes++ = (as_socket_t *) remote;
        as_thread_task((as_socket_t *) remote, __tcp_connect_to_remote_thread, remote);
    }
    *remotes = NULL;
    *data = client_data;
    *cb = __client_destroy;
    return as_tcp_read_start(clnt, __tcp_client_on_read);
}

static void *__tcp_connect_to_remote_thread(void *param)
{
    LOG_DEBUG("thread started!\n");
    as_tcp_t *remote = (as_tcp_t *) param;
    __remote_data_t *remote_data = (__remote_data_t *) as_socket_data((as_socket_t *) remote);
    while(1)
    {
        if(remote_data->status == 2)
            break;
        if(as_tcp_connect(remote, remote_data->dns_addr) != 0)
            break;
        if(remote_data->status == 2)
            break;
        if(as_tcp_read_start(remote, __tcp_remote_on_read) != 0)
            break;
        if(remote_data->status == 0)
            remote_data->status = 1;
        else
            break;
        pthread_mutex_lock(&remote_data->lock);
        while(1)
        {
            if(remote_data->status == 2)
            {
                pthread_mutex_unlock(&remote_data->lock);
                break;
            }
            if(remote_data->len != 0)
            {
                int rcode = as_tcp_write(remote, remote_data->buf, remote_data->len);
                free(remote_data->buf);
                remote_data->len = 0;
                if(rcode <= 0)
                {
                    pthread_mutex_unlock(&remote_data->lock);
                    break;
                }
            }
            pthread_cond_wait(&remote_data->signal, &remote_data->lock);
        }
        break;
    }
    pthread_mutex_lock(&remote_data->lock);
    while(1)
    {
        if(remote_data->status == 2)
            break;
        pthread_cond_wait(&remote_data->signal, &remote_data->lock);
    }
    pthread_mutex_unlock(&remote_data->lock);
    LOG_DEBUG("thread end!\n");
    if(remote_data->len != 0)
    {
        free(remote_data->buf);
    }
    free(remote_data);
    return NULL;
}

static int __tcp_remote_on_read(as_tcp_t *remote, __const__ char *buf, __const__ int len)
{
    char can_send = 0;
    struct sockaddr_storage addr;
    __remote_data_t *remote_data = (__remote_data_t *) as_socket_data((as_socket_t *) remote);
    as_tcp_t *client = (as_tcp_t *) remote_data->client;
    __client_data_t *client_data = remote_data->client_data;
    pthread_mutex_lock(&client_data->lock);
    if(client_data->first == NULL || client_data->first == (as_socket_t *) remote)
    {
        LOG_INFO("recv from: %s\n", address_str((struct sockaddr *) as_dest_addr((as_socket_t *) remote)));
        int rcode = __parse_dns_protocol((char *) buf, len, (struct sockaddr *) &addr, 1);
        if(rcode == 0)
        {
            LOG_DEBUG("parsed dns addr = %s\n", address_str((struct sockaddr *) &addr));
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
            LOG_DEBUG("parsed dns addr failed\n");
            if(rcode == -1)
                can_send = 1;
        }
    }
    if(can_send == 1)
    {
        LOG_DEBUG("send response\n");
        client_data->first = (as_socket_t *) remote;
        if(client_data->status != 0)
            as_tcp_write(client, buf, len);
    }
    pthread_mutex_unlock(&client_data->lock);
    return 0;
}

static int __tcp_client_on_read(as_tcp_t *clnt, __const__ char *buf, __const__ int len)
{
    __client_data_t *client_data = (__client_data_t *) as_socket_data((as_socket_t *) clnt);
    as_socket_t **remotes = client_data->remotes;
    as_socket_t *remote;
    __remote_data_t *remote_data;
    while((remote = *remotes++) != NULL)
    {
        remote_data = (__remote_data_t *) as_socket_data(remote);
        pthread_mutex_lock(&remote_data->lock);
        if(remote_data->len == 0)
        {
            remote_data->buf = (char *) malloc(len);
            memcpy(remote_data->buf, buf, len);
            remote_data->len = len;
        }
        else
        {
            remote_data->buf = (char *) realloc(remote_data->buf, remote_data->len + len);
            memcpy(remote_data->buf + remote_data->len, buf, len);
            remote_data->len += len;
        }
        pthread_cond_broadcast(&remote_data->signal);
        pthread_mutex_unlock(&remote_data->lock);
    }
    return 0;
}

static int __udp_client_on_connect(as_udp_t *srv, as_udp_t *clnt, void **data, as_socket_destroying_f *cb)
{
    int cnt = 0;
    struct sockaddr **dns_list;
    struct sockaddr *dns_addr;
    dns_list = china_dns_list;
    while(*dns_list++ != NULL)
        cnt++;
    dns_list = trustable_dns_list;
    while(*dns_list++ != NULL)
        cnt++;
    __client_data_t *client_data = (__client_data_t *) malloc(sizeof(__client_data_t));
    if(client_data == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    client_data->first = NULL;
    client_data->remotes = (as_socket_t **) malloc(sizeof(as_socket_t *) * (cnt + 1));
    if(client_data->remotes == NULL)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    if(pthread_mutex_init(&client_data->lock, NULL) != 0)
    {
        LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
        abort();
    }
    client_data->type = 2;
    client_data->status = 1;
    as_socket_t **remotes = client_data->remotes;
    dns_list = china_dns_list;
    while((dns_addr = *dns_list++) != NULL)
    {
        __remote_data_t *remote_data = (__remote_data_t *) malloc(sizeof(__remote_data_t));
        if(remote_data == NULL)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        remote_data->client = (as_socket_t *) clnt;
        remote_data->client_data = client_data;
        remote_data->type = 1;
        remote_data->dns_addr = dns_addr;
        remote_data->len = 0;
        remote_data->status = 0;
        as_udp_t *remote = as_udp_init(as_socket_loop((as_socket_t *) clnt), remote_data, __remote_udp_destroy);
        *remotes++ = (as_socket_t *) remote;
        if(as_udp_connect(remote, dns_addr) != 0)
            continue;
        as_udp_read_start(remote, __udp_remote_on_read);
        remote_data->status = 1;
    }
    dns_list = trustable_dns_list;
    while((dns_addr = *dns_list++) != NULL)
    {
        __remote_data_t *remote_data = (__remote_data_t *) malloc(sizeof(__remote_data_t));
        if(remote_data == NULL)
        {
            LOG_ERR(MSG_NOT_ENOUGH_MEMORY);
            abort();
        }
        remote_data->client = (as_socket_t *) clnt;
        remote_data->client_data = client_data;
        remote_data->type = 2;
        remote_data->dns_addr = dns_addr;
        remote_data->len = 0;
        remote_data->status = 0;
        as_udp_t *remote = as_udp_init(as_socket_loop((as_socket_t *) clnt), remote_data, __remote_udp_destroy);
        *remotes++ = (as_socket_t *) remote;
        if(as_udp_connect(remote, dns_addr) != 0)
            continue;
        as_udp_read_start(remote, __udp_remote_on_read);
        remote_data->status = 1;
    }
    *remotes = NULL;
    *data = client_data;
    *cb = __client_destroy;
    return as_udp_read_start(clnt, __udp_client_on_read);
}

static int __udp_client_on_read(as_udp_t *clnt, __const__ struct msghdr *msg, __const__ char *buf, __const__ int len)
{
    __client_data_t *client_data = (__client_data_t *) as_socket_data((as_socket_t *) clnt);
    as_socket_t **remotes = client_data->remotes;
    as_socket_t *remote;
    while((remote = *remotes++) != NULL)
        as_udp_write((as_udp_t *) remote, buf, len);
    return 0;
}

static int __udp_remote_on_read(as_udp_t *remote, __const__ struct msghdr *msg, __const__ char *buf, __const__ int len)
{
    char can_send = 0;
    int rcode;
    struct sockaddr_storage addr;
    __remote_data_t *remote_data = (__remote_data_t *) as_socket_data((as_socket_t *) remote);
    as_udp_t *client = (as_udp_t *) remote_data->client;
    __client_data_t *client_data = remote_data->client_data;
    pthread_mutex_lock(&client_data->lock);
    if(client_data->first == NULL || client_data->first == (as_socket_t *) remote)
    {
        LOG_DEBUG("recv from: %s\n", address_str((struct sockaddr *) as_dest_addr((as_socket_t *) remote)));
        rcode = __parse_dns_protocol((char *) buf, len, (struct sockaddr *) &addr, 2);
        if(rcode == 0)
        {
            LOG_DEBUG("parsed dns addr = %s\n", address_str((struct sockaddr *) &addr));
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
            LOG_DEBUG("parsed dns addr failed\n");
            if(remote_data->type == 2)
                can_send = 1;
        }
    }
    if(can_send == 1)
    {
        LOG_DEBUG("send response\n");
        if(rcode == 0)
        {
            LOG_INFO("query dns success, matched dns server: %s, ip = %s\n", address_str((struct sockaddr *) as_dest_addr((as_socket_t *) remote)), address_without_port_str((struct sockaddr *) &addr));
        }
        else
        {
            LOG_INFO("query dns failed, matched dns server: %s\n", address_str((struct sockaddr *) as_dest_addr((as_socket_t *) remote)));
        }
        client_data->first = (as_socket_t *) remote;
        if(client_data->status != 0)
            as_udp_write(client, buf, len);
    }
    pthread_mutex_unlock(&client_data->lock);
    return 0;
}
