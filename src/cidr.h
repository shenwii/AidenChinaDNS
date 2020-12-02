#ifndef _CIDR_H
#define _CIDR_H

#include <stdbool.h>
#include <sqlite3.h>
#include <sys/socket.h>

typedef sqlite3 cidr_t;

cidr_t *cidr_init();

int cidr_append(cidr_t *cidr, char *cidr_str);

bool cidr_match(cidr_t *cidr, struct sockaddr *addr);

int cidr_free(cidr_t *cidr);

#endif
