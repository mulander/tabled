/*	$Id: socket.c,v 1.2 2006/06/05 13:02:32 mbalmer Exp $	*/

/*
 * Copyright (c) 2003, 2004, 2005 Marc Balmer <marc@msys.ch>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "tabled.h"

ssize_t
to_recv(int s, void *buf, size_t len, int flags, struct timeval *timeout)
{
	int	n;
	fd_set	rset;

	FD_ZERO(&rset);
	FD_SET(s, &rset);
	
	if ((n = select(s + 1, &rset, NULL, NULL, timeout)) > 0)
		return recv(s, buf, len, flags);

	return n;
}

ssize_t
to_send(int s, const char *buf, size_t len, int flags, struct timeval *timeout)
{
	ssize_t	n;
	ssize_t	sent;
	ssize_t	retval;
	fd_set	wset;

	n = sent = 0;	

	FD_ZERO(&wset);
	FD_SET(s, &wset);
	while (sent < len) {
		if ((n = select(s + 1, NULL, &wset, NULL, timeout)) > 0) {
			if ((retval = send(s, buf + sent, len - sent, flags))
			    != -1)
				sent += retval;
		} else
			return n;
	}
	return sent;
}

SOCK *
fdsock(int sock)
{
	SOCK *sp;
	
	sp = calloc(sizeof(SOCK), 1);
	
	if (sp != NULL) {
		sp->sock = sock;
		sp->pos = sp->buf;
	}
	
	return sp;
}

int
to_readc(SOCK *sock, char *c, struct timeval *to)
{
	if (sock->size <= 0) {
		again:
		if ((sock->size = to_recv(sock->sock, sock->buf, SOCK_BUFSIZE,
		    0, to)) < 0) {
			if (errno == EINTR)
				goto again;
			return -1;
		} else if (sock->size == 0)
			return 0;
		sock->pos = sock->buf;
	}

	--sock->size;
	*c = *sock->pos++;
	return 1;
}

ssize_t 
to_readln(char *str, int size, SOCK *sock, struct timeval *to)
{
	ssize_t	n, rc;
	char	c, *p;

	p = str;
	for (n = 1; n < size; n++) {
		if ((rc = to_readc(sock, &c, to)) == 1) {
			*p++ = c;
			if (c == '\n')
				break;
		} else if (rc == 0) {
			*p = 0;
			return (n - 1);
		} else
			return -1;
	}
	*p = 0;
	return n;
}

void
sclose(SOCK *s)
{
	close(s->sock);
	free(s);
}
