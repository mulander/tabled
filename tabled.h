/*	$Id: tabled.h,v 1.1.1.1 2006/04/19 14:47:56 mbalmer Exp $	*/

/*
 * Copyright (c) 2006 Marc Balmer <mbalmer@openbsd.org>
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

#include <sys/cdefs.h>
#include <sys/time.h>

#include <stdio.h>
#include <unistd.h>

#define SOCK_BUFSIZE	1024
#define TABLED_USER	"_tabled"

typedef struct _SOCK {
	int	 sock;	
	char	 buf[SOCK_BUFSIZE];
	ssize_t	 size;
	char	*pos;
} SOCK;

extern int verbose;

__BEGIN_DECLS
extern SOCK *fdsock(int);
extern ssize_t to_recv(int, void *, size_t, int, struct timeval *);
extern ssize_t to_send(int, const char *, size_t, int, struct timeval *);
extern int to_readc(SOCK *, char *, struct timeval *);
extern ssize_t to_readln(char *, int, SOCK *, struct timeval *);
extern int *sputs(const char *, SOCK *, struct timeval *);
extern void sclose(SOCK *);
__END_DECLS
