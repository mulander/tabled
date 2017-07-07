/*	$Id: imsg.h,v 1.1.1.1 2006/04/19 14:47:56 mbalmer Exp $ */

/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/pfkeyv2.h>

#include <poll.h>
#include <stdarg.h>

#define	PFTABLE_LEN		16
#define ADR_LEN			64

#define	MAX_PKTSIZE		4096
#define	MIN_HOLDTIME		3
#define	READ_BUF_SIZE		65535
#define	RT_BUF_SIZE		16384
#define	MAX_RTSOCK_BUF		128 * 1024

struct buf {
	TAILQ_ENTRY(buf)	 entry;
	u_char			*buf;
	size_t			 size;
	size_t			 wpos;
	size_t			 rpos;
	int			 fd;
};

struct msgbuf {
	TAILQ_HEAD(, buf)	 bufs;
	u_int32_t		 queued;
	int			 fd;
};

struct buf_read {
	u_char			 buf[READ_BUF_SIZE];
	u_char			*rptr;
	size_t			 wpos;
};

/* ipc messages */

#define	IMSG_HEADER_SIZE	sizeof(struct imsg_hdr)
#define	MAX_IMSGSIZE		8192

struct imsg_fd {
	TAILQ_ENTRY(imsg_fd)	entry;
	int			fd;
};

struct imsgbuf {
	TAILQ_HEAD(fds, imsg_fd)	fds;
	struct buf_read			r;
	struct msgbuf			w;
	int				fd;
	pid_t				pid;
};

enum imsg_type {
	IMSG_RECONFIGURE,
	IMSG_PFTABLE_ADD,
	IMSG_PFTABLE_DEL
};

struct imsg_hdr {
	u_int32_t	peerid;
	pid_t		pid;
	enum imsg_type	type;
	u_int16_t	len;
};

struct imsg {
	struct imsg_hdr	 hdr;
	void		*data;
};

struct pftable_msg {
	char		addr[ADR_LEN];
	char		pftable[PFTABLE_LEN];
	long		duration;
	u_int8_t	len;
};

/*
 * per connection statistics
 * if the connection is aborted, msgs is 0
 */
struct stats_msg {
	u_int32_t 	msgs;
	u_int32_t	aborts;
	u_int32_t 	spam;
	u_int32_t 	virus;
	u_int32_t 	unwanted;
	u_int32_t	err;
};

void	 send_imsg_session(int, pid_t, void *, u_int16_t);

/* buffer.c */
struct buf	*buf_open(size_t);
int		 buf_add(struct buf *, void *, size_t);
void		*buf_reserve(struct buf *, size_t);
int		 buf_close(struct msgbuf *, struct buf *);
int		 buf_write(int, struct buf *);
void		 buf_free(struct buf *);
void		 msgbuf_init(struct msgbuf *);
void		 msgbuf_clear(struct msgbuf *);
int		 msgbuf_write(struct msgbuf *);
int		 msgbuf_writebound(struct msgbuf *);
int		 msgbuf_unbounded(struct msgbuf *msgbuf);

/* imsg.c */
void	 imsg_init(struct imsgbuf *, int);
int	 imsg_read(struct imsgbuf *);
int	 imsg_get(struct imsgbuf *, struct imsg *);
int	 imsg_compose(struct imsgbuf *, enum imsg_type, u_int32_t, pid_t, int,
	    void *, u_int16_t);
struct buf	*imsg_create(enum imsg_type, u_int32_t, pid_t,
		    u_int16_t);
int	 imsg_add(struct buf *, void *, u_int16_t);
int	 imsg_close(struct imsgbuf *, struct buf *);
void	 imsg_free(struct imsg *);
int	 imsg_get_fd(struct imsgbuf *);

int	pftable_exists(const char *);
int	pftable_addr_add(struct pftable_msg *);
int	pftable_addr_del(struct pftable_msg *);
int	pftable_timeout(void);
