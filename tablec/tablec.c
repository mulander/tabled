/*	$Id: tablec.c,v 1.3 2007/04/14 06:25:57 mbalmer Exp $	*/

/*
 * Copyright (c) 2007 Daniel Hartmeier <daniel@msys.ch>
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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int verbose = 0;

static int
get_fd(const char *addr, const char *port)
{
	int fd = -1, err;
	struct addrinfo hints, *res, *res0;
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	if ((err = getaddrinfo(addr, port, &hints, &res0))) {
		fprintf(stderr, "getaddrinfo: %s:%s: %s\n",
		    addr, port, gai_strerror(err));
		return (-1);
	}
	for (res = res0; res != NULL; res = res->ai_next) {
		err = getnameinfo(res->ai_addr, res->ai_addrlen,
		    hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
		    NI_NUMERICHOST | NI_NUMERICSERV);
		if (err) {
			fprintf(stderr, "getnameinfo: %s:%s: %s\n", addr, port,
			    gai_strerror(err));
			continue;
		}
		if (verbose)
			printf("connecting to %s port %s... ", hbuf, sbuf);
		fd = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);
		if (fd < 0) {
			if (verbose)
			printf("socket: %s\n", strerror(errno));
			continue;
		}
		if (connect(fd, res->ai_addr, res->ai_addrlen)) {
			if (verbose)
				printf("connect: %s\n", strerror(errno));
			close(fd);
			fd = -1;
			continue;
		}
		if (verbose)
			printf("established\n");
		break;
	}
	return (fd);
}

static void
handle_entry(int fd, const char *cmd, const char *table, const char *addr,
    const char *secret)
{
	char s[8192];
	int r;

	snprintf(s, sizeof(s), "%s %s %s", cmd, table, addr);
	if (secret[0]) {
		SHA1_CTX ctx;
		char digest[SHA1_DIGEST_STRING_LENGTH];

		SHA1Init(&ctx);
		SHA1Update(&ctx, cmd, strlen(cmd));
		SHA1Update(&ctx, table, strlen(table));
		SHA1Update(&ctx, addr, strlen(addr));
		SHA1Update(&ctx, secret, strlen(secret));
		SHA1End(&ctx, digest);
		snprintf(s + strlen(s), sizeof(s) - strlen(s), " %s", digest);
	}
	strlcat(s, "\n", sizeof(s));
	r = write(fd, s, strlen(s));
	if (r < 0)
		fprintf(stderr, "write: %s\n", strerror(errno));
	else if (r != strlen(s))
		fprintf(stderr, "write: short write (%d < %d)\n",
		    r, (int)strlen(s));
	else if (verbose)
		printf("wrote: %s", s);
}

static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-v] [-s secret] [-h host:port] "
	    "-t table -c command [-f file] addr addr ...\n", __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	int ch;
	char hostname[NI_MAXHOST] = "", portname[NI_MAXSERV] = "";
	const char *secret = "";
	const char *filename = "";
	const char *table = NULL;
	char cmd[32];
	int fd;

	while ((ch = getopt(argc, argv, "c:f:h:s:t:v")) != -1) {
		switch (ch) {
		case 'c':
			strlcpy(cmd, optarg, sizeof(cmd));
			break;
		case 'f':
			filename = optarg;
			break;
		case 'h': {
			char *p;

			strlcpy(hostname, optarg, sizeof(hostname));
			p = strrchr(hostname, ':');
			if (p == NULL)
				usage();
			*p++ = 0;
			strlcpy(portname, p, sizeof(portname));
			break;
		}
		case 's':
			secret = optarg;
			break;
		case 't':
			table = optarg;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
		}
	}
	if (!cmd[0] || !table)
		usage();

	if (hostname[0] && portname[0]) {
		fd = get_fd(hostname, portname);
		if (fd == -1) {
			fprintf(stderr, "could not connect to %s port %s\n",
			    hostname, portname);
			return (1);
		}
	} else
		fd = fileno(stdout);

	if (filename[0]) {
		FILE *f;
		char s[8192];

		if (!strcmp(filename, "-"))
			f = stdin;
		else {
			if ((f = fopen(filename, "r")) == NULL) {
				fprintf(stderr, "fopen: %s: %s\n", filename,
				    strerror(errno));
				close(fd);
				return (1);
			}
		}
		while (fgets(s, sizeof(s), f) != NULL) {
			if (strlen(s) > 0)
				s[strlen(s) - 1] = 0;
			handle_entry(fd, cmd, table, s, secret);
		}
		fclose(f);
	}
	while (optind < argc)
		handle_entry(fd, cmd, table, argv[optind++], secret);

	if (fd != fileno(stdout))
		close(fd);
	return (0);
}
