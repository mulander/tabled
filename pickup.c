/*	$Id: pickup.c,v 1.10 2007/04/05 13:49:14 dhartmei Exp $	*/

/*
 * Copyright (c) 2006, 2007 Marc Balmer <mbalmer@openbsd.org>
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

#include <sys/time.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <sha1.h>
#include <netdb.h>

#include "pathnames.h"
#include "tabled.h"

#include "imsg.h"

#include <poll.h>
#include <sys/syslimits.h>

#define MAX_FILE	1024
#define MAXLEN		256
#define MAXSTR		256

#define LOG_UNSET	-1

extern char	*sock;
extern char	*listen_addr;
extern char	*secret;

extern int	 verbose;
extern char	*cfgfile;
extern int	 log_facility;

struct imsgbuf	*ibuf_main;

extern char *__progname;

static void pf_table_add(const char *, const char *, long);
static void pf_table_clr(const char *, const char *, long);
static void imsg_commit();

void
p_sighdlr(int signum)
{
	switch (signum) {
	case SIGHUP:
		break;
	}
}

static void
pf_table_add(const char *table, const char *addr, long duration)
{
	pid_t pid;
	struct pftable_msg m;

	if (table == NULL || addr == NULL)
		return;
	
	pid = getpid();

	strlcpy(m.pftable, table, PFTABLE_LEN);
	strlcpy(m.addr, addr, ADR_LEN);
	m.duration = duration;
	m.len = 0;
	
	if (imsg_compose(ibuf_main, IMSG_PFTABLE_ADD, 0, pid, -1, &m,
	    sizeof(m)) != -1) 
		imsg_commit();
}

static void
pf_table_clr(const char *table, const char *addr, long duration)
{
	pid_t pid;
	struct pftable_msg m;

	if (table == NULL || addr == NULL)
		return;
	
	pid = getpid();

	strlcpy(m.pftable, table, PFTABLE_LEN);
	strlcpy(m.addr, addr, ADR_LEN);
	m.duration = duration;
	m.len = 0;
	
	if (imsg_compose(ibuf_main, IMSG_PFTABLE_DEL, 0, pid, -1, &m,
	    sizeof(m)) != -1)
		imsg_commit();
}

static void
imsg_commit()
{
	struct pollfd	pfd[1];
	int nfds;

	for (;;) {
		bzero(pfd, sizeof(pfd));
		pfd[0].fd = ibuf_main->fd;
		pfd[0].events = POLLOUT;

		if ((nfds = poll(pfd, 1, INFTIM)) == -1)
			if (errno != EINTR)
				errx(1, "engine: poll error");

		if (nfds > 0 && ibuf_main->w.queued) {
			if (msgbuf_write(&ibuf_main->w) < 0)
				errx(1, "pipe write error");
			else
				break; /* XXX All bytes sent? */
		}
	}
}

#define MAXCONN		64
#define MAXLINESIZE	8192
static struct connection {
	int			 fd;
	char			 buf[MAXLINESIZE];
	size_t			 pos;
} connections[MAXCONN];

static void
handle_line(char *line)
{
	char	*p, *hash, *cmd, *table, *adr;

	p = line;
	if (((cmd = strsep(&p, " \t")) == NULL) ||
	    ((table = strsep(&p, " \t")) == NULL) ||
	    ((adr = strsep(&p, " \t")) == NULL) ||
	    (secret != NULL && (hash = strsep(&p, " \t")) == NULL)) {
		syslog(LOG_WARNING, "handle_line: parse error");
		return;
	}
	if (secret != NULL) {
		SHA1_CTX	 ctx;
		char		 digest[SHA1_DIGEST_STRING_LENGTH];

		SHA1Init(&ctx);
		SHA1Update(&ctx, cmd, strlen(cmd));
		SHA1Update(&ctx, table, strlen(table));
		SHA1Update(&ctx, adr, strlen(adr));
		SHA1Update(&ctx, secret, strlen(secret));
		SHA1End(&ctx, digest);
		if (strcmp(digest, hash)) {
			syslog(LOG_WARNING, "handle_line: hash mismatch");
			return;
		}
	}
	if (!strcmp(cmd, "add"))
		pf_table_add(table, adr, 0);
	else if (!strcmp(cmd, "clr"))
		pf_table_clr(table, adr, 0);
	else 
		syslog(LOG_WARNING, "handle_line: unknown cmd '%s'", cmd);
}

static void
handle_read(struct connection *c, const char *buf, int len)
{
	int i;

	for (i = 0; i < len; ++i) {
		c->buf[c->pos] = buf[i];
		if (buf[i] == '\n' || c->pos == sizeof(c->buf) - 2) {
			if (c->pos > 0 && c->buf[c->pos - 1] == '\r')
				c->buf[c->pos - 1] = 0;
			else if (c->buf[c->pos] == '\n')
				c->buf[c->pos] = 0;
			else
				c->buf[c->pos + 1] = 0;
			handle_line(c->buf);
			c->pos = 0;
		} else
			c->pos++;
	}
}

#define MAXLISTEN	16

int
p_main(int pipe_m2e[2])
{
	struct stat	 stb;
	struct passwd	*pw;
	int		 nullfd;
	int		 pid;
	int		 listen_fd[MAXLISTEN];
	int		 i;

	switch (pid = fork()) {
	case -1:
		errx(1, "can't fork");
	case 0:
		break;
	default:
		return pid;
	}

	if ((pw = getpwnam(TABLED_USER)) == NULL)
		errx(1, "getpwnam");

	if ((nullfd = open(_PATH_DEVNULL, O_RDWR, 0)) == -1)
		exit(1);

	if (stat(pw->pw_dir, &stb) == -1)
		errx(1, "stat");
	if (stb.st_uid != 0 || (stb.st_mode & (S_IWGRP|S_IWOTH)) != 0)
		errx(1, "bad privsep dir permissions");

	for (i = 0; i < MAXCONN; ++i) {
		memset(&connections[i], 0, sizeof(connections[i]));
		connections[i].fd = -1;
	}
	for (i = 0; i < MAXLISTEN; ++i)
		listen_fd[i] = -1;

	if (sock != NULL) {
		connections[0].fd = open(sock, O_RDONLY | O_NONBLOCK, 0);
		if (connections[0].fd == -1)
			err(1, "open: %s", sock);
	}

	if (listen_addr != NULL) {
		char		*listen_port;
		struct addrinfo	 hints, *res, *res0;
		int		 err, val;

		listen_port = strrchr(listen_addr, ':');
		if (listen_port == NULL)
			errx(1, "invalid host:port '%s'", listen_addr);
		*listen_port++ = 0;

		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_PASSIVE;
		err = getaddrinfo(listen_addr, listen_port, &hints, &res0);
		if (err) {
			fprintf(stderr, "getaddrinfo: %s:%s: %s\n",
			    listen_addr, listen_port, gai_strerror(err));
			exit(1);
		}
		i = 0;
		for (res = res0; res != NULL && i < MAXLISTEN;
		    res = res->ai_next) {
			listen_fd[i] = socket(res->ai_family, res->ai_socktype,
			    res->ai_protocol);
			if (listen_fd[i] < 0)
				continue;
			if (fcntl(listen_fd[i], F_SETFL, fcntl(listen_fd[i],
			    F_GETFL) | O_NONBLOCK)) {
				fprintf(stderr, "fcntl: %s\n",
				    strerror(errno));
				close(listen_fd[i]);
				continue;
			}
			val = 1;
			if (setsockopt(listen_fd[i], SOL_SOCKET, SO_REUSEADDR,
			    (const char *)&val,
			    sizeof(val))) {
				fprintf(stderr, "setsockopt: %s\n",
				    strerror(errno));
				close(listen_fd[i]);
				continue;
			}
			if (bind(listen_fd[i], res->ai_addr,
			    res->ai_addrlen)) {
				fprintf(stderr, "bind: %s\n", strerror(errno));
				close(listen_fd[i]);
				continue;
			}
			if (listen(listen_fd[i], 5)) {
				fprintf(stderr, "listen: %s\n",
				    strerror(errno));
				close(listen_fd[i]);
				continue;
			}
			i++;
		}
	}

	if (chroot(pw->pw_dir) == -1)
		errx(1, "chroot");
	if (chdir("/") == -1)
		errx(1, "chdir(\"/\")");

	if (!verbose) {
		dup2(nullfd, STDIN_FILENO);
		dup2(nullfd, STDOUT_FILENO);
		dup2(nullfd, STDERR_FILENO);
	}
	close(nullfd);

	setproctitle("pickup");

	/* imsg stuff */
	close(pipe_m2e[0]);
	if ((ibuf_main = malloc(sizeof(struct imsgbuf))) == NULL)
		errx(1, "memory error");
	imsg_init(ibuf_main, pipe_m2e[1]);

	/* Do the work */
	while (1) {
		struct timeval	 tv;
		fd_set		 readfds;
		int		 maxfd = -1;
		int		 r;

		FD_ZERO(&readfds);
		for (i = 0; i < MAXLISTEN; ++i) {
			if (listen_fd[i] != -1) {
				FD_SET(listen_fd[i], &readfds);
				if (listen_fd[i] > maxfd)
					maxfd = listen_fd[i];
			}
		}
		for (i = 0; i < MAXCONN; ++i) {
			if (connections[i].fd != -1) {
				FD_SET(connections[i].fd, &readfds);
				if (connections[i].fd > maxfd)
					maxfd = connections[i].fd;
			}
		}
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		r = select(maxfd + 1, &readfds, NULL, NULL, &tv);
		if (r < 0) {
			if (errno != EINTR) {
				syslog(LOG_ERR, "p_main: select: %s",
				    strerror(errno));
				break;
			}
		} else if (r == 0)
			continue;

		for (i = 0; i < MAXLISTEN; ++i) {
			struct sockaddr_storage	 sa;
			socklen_t		 len;
			int			 client_fd, err;
			char			 hbuf[NI_MAXHOST];

			if (listen_fd[i] == -1 ||
			    !FD_ISSET(listen_fd[i], &readfds))
				continue;
			memset(&sa, 0, sizeof(sa));
			len = sizeof(sa);
			client_fd = accept(listen_fd[i],
			    (struct sockaddr *)&sa, &len);
			if (client_fd < 0) {
				syslog(LOG_ERR, "p_main: accept: %s",
				    strerror(errno));
				break;
			}
			err = getnameinfo((struct sockaddr *)&sa, len,
			    hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST);
			if (err)
				syslog(LOG_ERR, "p_main: getnameinfo: %s",
				    gai_strerror(err));
			else
				syslog(LOG_INFO, "connection from %s", hbuf);
			if (fcntl(client_fd, F_SETFL,
			    fcntl(client_fd, F_GETFL) | O_NONBLOCK)) {
				syslog(LOG_ERR, "p_main: fcntl: %s",
				    strerror(errno));
				close(client_fd);
				break;
			}
			for (i = 0; i < MAXCONN; ++i)
				if (connections[i].fd == -1)
					break;
			if (i == MAXCONN) {
				syslog(LOG_ERR, "p_main: MAXCONN (%d) reached",
				    (int)MAXCONN);
				close(client_fd);
			} else {
				memset(&connections[i], 0,
				    sizeof(connections[i]));
				connections[i].fd = client_fd;
			}
		}

		for (i = 0; i < MAXCONN; ++i) {
			char	 buf[8192];
			int	 len;

			if (connections[i].fd == -1 ||
			    !FD_ISSET(connections[i].fd, &readfds))
				continue;
			len = read(connections[i].fd, buf, sizeof(buf));
			if (len < 0) {
				if (errno == EINTR || errno == EAGAIN)
					continue;
				syslog(LOG_ERR, "p_main: read: %s",
				    strerror(errno));
				len = 0;
			}
			if (len == 0) {
				syslog(LOG_INFO, "connection closed by peer");
				close(connections[i].fd);
				connections[i].fd = -1;
			} else
				handle_read(&connections[i], buf, len);
		}

	}


	closelog();
	_exit(2);
}
