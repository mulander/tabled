/*	$Id: tabled.c,v 1.3 2007/04/04 12:38:18 dhartmei Exp $	*/

/*
 * Copyright (c) 2006 Marc Balmer <marc@msys.ch>
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
#include <sys/stat.h>
#include <sys/wait.h>

#include <ctype.h>
#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "pathnames.h"
#include "tabled.h"

#include "imsg.h"

#include <sys/syslimits.h>

#define MAX_FILE	1024
#define MAXLEN		256
#define MAXSTR		256
#define POLL_MAX	1

#define LOG_UNSET	-1

char	*sock;
char	*listen_addr;
char	*secret;

int	 verbose;
char	*cfgfile;
int	 log_facility;

struct imsgbuf	*ibuf_p;

extern char *__progname;

volatile sig_atomic_t quit = 0;
volatile sig_atomic_t child_quit = 0;
volatile sig_atomic_t reconfig = 0;
volatile sig_atomic_t alrm_expired = 0;

int	 dev = -1;

int dispatch_imsg(struct imsgbuf *);

extern void tabled_init(void);
extern int p_main(int[2]);

static void
sighdlr(int signum)
{
	switch (signum) {
	case SIGCHLD:
		child_quit = 1;
		break;
	case SIGINT:
	case SIGTERM:
		quit = 1;
		break;
	case SIGHUP:
		/* reconfigure */
		reconfig = 1;
		break;
	case SIGALRM:
		alrm_expired = 1;
	}
}

__dead static void
usage(void)
{
	fprintf(stderr, "usage: %s [-v] [-C configfile] [-s socket]\n",
	    __progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	int		 ch;
	struct pollfd	 pfd[1];
	pid_t		 child_pid, pid;
	int		 pipe_m2p[2];
	int		 nfds;
	int		 flags;

	/* Set initial values */
	sock = NULL;
	listen_addr = NULL;
	secret = NULL;
	cfgfile = _PATH_CFGFILE;

	log_facility = LOG_UNSET;

	/* Process the commandline */
	while ((ch = getopt(argc, argv, "C:s:v")) != -1) {
		switch (ch) {
		case 'C':
			cfgfile = optarg;
			break;
		case 's':
			sock = optarg;
			break;
		case 'v':
			++verbose;
			break;
		default:
			usage();
		}
	}

	/* Read config file */
	tabled_init();

	/* Set default values if some variables are not set */
	if (sock == NULL)
		sock = strdup(_PATH_SOCKET);
	if (log_facility == LOG_UNSET)
		log_facility = LOG_DAEMON;

	openlog(__progname, verbose ? LOG_CONS | LOG_NDELAY | LOG_PID |
	    LOG_PERROR : LOG_CONS | LOG_NDELAY | LOG_PID, log_facility);

	if (geteuid())
		errx(1, "tabled: need root privileges\n");

	if (getpwnam(TABLED_USER) == NULL)
		errx(1, "tabled: unknown user %s\n", TABLED_USER);
	endpwent();

	if (verbose == 0 &&  daemon(0, 0))
		err(1, "can't run as daemon");

	while (!quit) {

		/* Setup imsg stuff, this is a one-way com only */
		if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pipe_m2p) == -1)
			errx(1, "imsg setup failed");
		if ((flags = fcntl(pipe_m2p[0], F_GETFL, 0)) == -1)
			errx(1, "fcntl failed");
		flags |= O_NONBLOCK;
		if (fcntl(pipe_m2p[0], F_SETFL, flags) == -1)
			errx(1, "fcntl can't set flags");
		if ((flags = fcntl(pipe_m2p[1], F_GETFL, 0)) == -1)
			errx(1, "fcntl failed");
		flags |= O_NONBLOCK;
		if (fcntl(pipe_m2p[1], F_SETFL, flags) == -1)
			errx(1, "fcntl can't set flags");

		/*
		 * Fork into two processes, one to run privileged, one
		 * to pickup commands
		 */
		if (verbose)
			warnx("start unprivileged child process");

		child_quit = 0;
		child_pid = p_main(pipe_m2p);

		/* We are the privileged process */
		setproctitle("parent");

		signal(SIGCHLD, sighdlr);
		signal(SIGINT, sighdlr);
		signal(SIGTERM, sighdlr);
		signal(SIGHUP, sighdlr);

		close(pipe_m2p[1]);

		if ((ibuf_p = malloc(sizeof(struct imsgbuf))) == NULL)
			errx(1, "memory error");

		imsg_init(ibuf_p, pipe_m2p[0]);

		while (!quit && !child_quit) {
			pfd[0].fd = ibuf_p->fd;
			pfd[0].events = POLLIN;
			if ((nfds = poll(pfd, 1, 1000)) == -1) {
				if (errno != EINTR) {
					syslog(LOG_WARNING, "main: poll error");
					/* quit = 1; */
				}
			} else if (nfds > 0 && pfd[0].revents & POLLIN) {
				/* nfds --; */
				if (!child_quit && dispatch_imsg(ibuf_p) == -1)
					quit = 1;
			}

			if (pftable_timeout())
				syslog(LOG_WARNING, "can not timeout pf "
				    "tables");
			if (child_quit && verbose)
				warnx("child process terminated");

		}

		if (quit && !child_quit) {	/* XXX is this necessary? */
			sleep(1);
			if (!child_quit) {
				if (verbose)
					warnx("signalling child process to "
					    "terminate");
				kill(child_pid, SIGTERM);
			}
		}

		if (verbose)
			warnx("waiting for all child processes to terminate");

		do {
			if ((pid = wait(NULL)) == -1 &&
			    errno != EINTR && errno != ECHILD)
				errx(1, "wait");
		} while (pid != child_pid || (pid == -1 && errno == EINTR));

		if (verbose)
			warnx("child processes have terminated");

		msgbuf_clear(&ibuf_p->w);
		free(ibuf_p);
		close(pipe_m2p[0]);

		signal(SIGCHLD, SIG_DFL);
		signal(SIGINT, SIG_DFL);
		signal(SIGTERM, SIG_DFL);
		signal(SIGHUP, SIG_DFL);
		signal(SIGALRM, SIG_DFL);

		/* Wait one second before restarting the child process */
		if (!quit)
			sleep(1);
	}

	closelog();

	return 0;
}

int
dispatch_imsg(struct imsgbuf *ibuf)
{
	struct imsg	imsg;
	int		n;
	int		rv;

	if ((n = imsg_read(ibuf)) == -1)
		return -1;

	if (n == 0) { /* connection closed */
		syslog(LOG_WARNING, "dispatch_imsg in main: pipe closed");
		return -1;
	}

	rv = 0;
	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			return -1;

		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_RECONFIGURE:
			break;
		case IMSG_PFTABLE_ADD:
			if (imsg.hdr.len != IMSG_HEADER_SIZE +
			    sizeof(struct pftable_msg))
				syslog(LOG_WARNING, "wrong imsg size");
			else if (pftable_addr_add(imsg.data) != 0) {
				rv = 1;
			}
			break;
		case IMSG_PFTABLE_DEL:
			if (imsg.hdr.len != IMSG_HEADER_SIZE +
			    sizeof(struct pftable_msg))
				syslog(LOG_WARNING, "wrong imsg size");
			else if (pftable_addr_del(imsg.data) != 0) {
				rv = 1;
			}
			break;
		}
		imsg_free(&imsg);
		if (rv != 0)
			return rv;
	}
	return 0;
}
