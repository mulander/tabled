/*	$Id: pftable.c,v 1.4 2006/11/13 12:07:35 mbalmer Exp $ */

/*
 * Copyright (c) 2005, 2006 Marc Balmer <marc@msys.ch>
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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/pfvar.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "tabled.h"
#include "imsg.h"


extern int dev;

struct timed_entry {
	char				*pftable;
	char				*host;
	time_t				 expiry;
	unsigned long			 what;
	SLIST_ENTRY(timed_entry)	 entries;
};

SLIST_HEAD(, timed_entry) thead = SLIST_HEAD_INITIALIZER(thead);

int
pftable_exists(const char *name)
{
	struct pfioc_table tio;
	struct pfr_astats dummy;

	if (getuid())
		return 0;

	if (dev == -1 && ((dev = open("/dev/pf", O_RDWR)) == -1))
		errx(1, "can't open(/dev/pf)");

	bzero(&tio, sizeof(tio));
	strlcpy(tio.pfrio_table.pfrt_name, name,
	    sizeof(tio.pfrio_table.pfrt_name));
	tio.pfrio_buffer = &dummy;
	tio.pfrio_esize = sizeof(dummy);
	tio.pfrio_size = 1;

	if (ioctl(dev, DIOCRGETASTATS, &tio) != 0)
		return (-1);

	return (0);
}


/* imsg handlers */
static int
pftable_modify(char *pftable, char *host, unsigned long what)
{
	struct hostent *h;
	struct pfioc_table tio;
	int naddr;
	char **p;
	struct pfr_addr *addr, *a;
	struct in_addr iadr;

	if (dev == -1 && ((dev = open("/dev/pf", O_RDWR)) == -1))
		syslog(LOG_ERR, "pftable_modify: can not open /dev/pf");

	bzero(&tio, sizeof(tio));

	if (inet_aton(host, &iadr) == 0) {
		h = gethostbyname(host);
		if (h == NULL) {
			syslog(LOG_WARNING, "pftable_modify: can not resolve "
			    "hostname %s", host);
			return -1;
		}

		for (naddr = 0, p = h->h_addr_list; *p != NULL; p++, naddr++)
			;

		if ((addr = calloc(naddr, sizeof(struct pfr_addr))) == NULL) {
			syslog(LOG_ERR, "pftable_modify: memory error");
			return -1;
		}

		for (a = addr, p = h->h_addr_list; *p != NULL; p++, a++) {
			a->pfra_af = AF_INET;
			a->pfra_net = 32;
			memcpy(&a->pfra_u._pfra_ip4addr, *p, 4); 
		}
	} else {
		naddr = 1;
		if ((addr = malloc(sizeof(struct pfr_addr))) == NULL) {
			syslog(LOG_ERR, "pftable_modify: memory error");
			return -1;
		}
		bzero(addr, sizeof(struct pfr_addr));
		addr->pfra_af = AF_INET;
		addr->pfra_net = 32;
		memcpy(&addr->pfra_u._pfra_ip4addr, &iadr, 4);
	}

	bzero(&tio, sizeof(tio));
	h = gethostbyname(host);
	if (h == NULL) { /* XXX instead of returning, add at least the addr */
		syslog(LOG_WARNING, "pftable_modify: can not resolve "
		    "hostname %s", host);
		return -1;
	}

	for (naddr = 0, p = h->h_addr_list; *p != NULL; p++, naddr++)
		;

	if ((addr = calloc(naddr, sizeof(struct pfr_addr))) == NULL) {
		syslog(LOG_ERR, "pftable_modify: memory error");
		return -1;
	}

	for (a = addr, p = h->h_addr_list; *p != NULL; p++, a++) {
		a->pfra_af = AF_INET;
		a->pfra_net = 32;
		memcpy(&a->pfra_u._pfra_ip4addr, *p, 4); 
	}
	strlcpy(tio.pfrio_table.pfrt_name, pftable,
	    sizeof(tio.pfrio_table.pfrt_name));
	tio.pfrio_buffer = addr;
	tio.pfrio_esize = sizeof(*addr);
	tio.pfrio_size = naddr;

	if (ioctl(dev, what, &tio) != 0) {
		if (what == DIOCRADDADDRS)
			syslog(LOG_WARNING, "pftable_modify: can not add host "
			    "%s to table %s", host, pftable);
		else
			syslog(LOG_WARNING, "pftable_modify: can not delete "
			    "host %s from table %s", host, pftable);
		return -1;
	} else {
		if (what == DIOCRADDADDRS)
			syslog(LOG_INFO, "added %d/%d addresses for host %s "
			    "to table %s",
			    tio.pfrio_nadd, naddr, host, pftable);
		else
			syslog(LOG_INFO, "deleted %d/%d addresses for host %s "
			    "from table %s",
			    tio.pfrio_ndel, naddr, host, pftable);
	}

	return 0;
}

int
pftable_addr_add(struct pftable_msg *m)
{
	int retval = 0;
	struct timed_entry *te;

	retval = pftable_modify(m->pftable, m->addr, DIOCRADDADDRS);
	if (!retval && m->duration > 0) {

		/* Check if there is already an entry for this host */
		SLIST_FOREACH(te, &thead, entries) {
			if (!strcmp(te->pftable, m->pftable) &&
			    !strcmp(te->host, m->addr) &&
			    te->what == DIOCRDELADDRS) {
				time(&te->expiry);
				te->expiry += (time_t)m->duration;
				return 0;
			}
		}

		/* Add this entry to the timeout list */
		if ((te = malloc(sizeof(struct timed_entry))) == NULL) {
			syslog(LOG_ERR, "pftable_modify: memory error");
			return -1;
		}
		bzero(te, sizeof(struct timed_entry));
		time(&te->expiry);
		te->expiry += (time_t)m->duration;
		if ((te->pftable = strdup(m->pftable)) == NULL) {
			syslog(LOG_ERR, "pftable_modify: memory allocation "
			    "error");
			free(te);
			return -1;
		}
		if ((te->host = strdup(m->addr)) == NULL) {
			syslog(LOG_ERR, "pftable_modify: memory allocation "
			    "error");
			free(te->pftable);
			free(te);
			return -1;
		}
		te->what = DIOCRDELADDRS;
		SLIST_INSERT_HEAD(&thead, te, entries);
	}

	return retval;
}

int
pftable_addr_del(struct pftable_msg *m)
{
	int retval = 0;
	struct timed_entry *te;

	retval = pftable_modify(m->pftable, m->addr, DIOCRDELADDRS);
	if (retval || m->duration <= 0)
		return retval;

	/* Check if there is already an entry for this host */
	SLIST_FOREACH(te, &thead, entries) {
		if (!strcmp(te->pftable, m->pftable)
		    && !strcmp(te->host, m->addr)
		    && te->what == DIOCRADDADDRS) {
			time(&te->expiry);
			te->expiry += (time_t)m->duration;
			return 0;
		}
	}

	/* Add this entry to the timeout list */
	if ((te = malloc(sizeof(struct timed_entry))) == NULL) {
		syslog(LOG_ERR, "pftable_modify: memory error");
		return -1;
	}
	bzero(te, sizeof(struct timed_entry));
	time(&te->expiry);
	te->expiry += (time_t)m->duration;
	if ((te->pftable = strdup(m->pftable)) == NULL) {
		syslog(LOG_ERR, "pftable_modify: memory allocation error");
		free(te);
		return -1;
	}
	if ((te->host = strdup(m->addr)) == NULL) {
		syslog(LOG_ERR, "pftable_modify: memory allocation error");
		free(te->pftable);
		free(te);
		return -1;
	}
	te->what = DIOCRADDADDRS;
	SLIST_INSERT_HEAD(&thead, te, entries);

	return retval;
}

int
pftable_timeout(void)
{
	time_t now;
	struct timed_entry *te, *next;
	int retval = 0;

	if (SLIST_EMPTY(&thead))
		return retval;

	time(&now);
	te = SLIST_FIRST(&thead);
	while (te != NULL) {
		next = SLIST_NEXT(te, entries);
		if (te->expiry <= now) {
			retval = pftable_modify(te->pftable, te->host,
			    te->what);
			SLIST_REMOVE(&thead, te, timed_entry, entries);
			free(te->pftable);
			free(te->host);
			free(te);
		}
		te = next;
	}

	return retval;
}
