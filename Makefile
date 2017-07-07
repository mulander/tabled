# $Id: Makefile,v 1.12 2007/04/14 06:25:56 mbalmer Exp $

PROG=		tabled
SRCS=		tabled.c pickup.c imsg.c buffer.c pftable.c socket.c \
		parse.y scan.l

SUBDIR=		tablec

CFLAGS+= 	-Wall -I{.CURDIR}

YFLAGS=		-d
LFLAGS=		-olex.yy.c
LINTFLAGS+=	-u

CLEANFILES+=	y.tab.h rt-dynamic

MAN=		tabled.8 tabled.conf.5
MANDIR=		/usr/local/man/cat

BINOWN = 	root
BINMOD =	0555
BINDIR= 	/usr/local/sbin

VERSION=	1.0.5
PUBDIR=		/var/www/ftp/pub/sources/tabled

publish: cleandir
	mkdir -p ${PUBDIR}
	(cd ..; tar -czvf ${PUBDIR}/${PROG}-${VERSION}.tgz -s \
	    /${PROG}/${PROG}-${VERSION}/ \
	    `find ${PROG} -type f | grep -v CVS`; \
	    md5 ${PUBDIR}/${PROG}-${VERSION}.tgz > \
	    ${PUBDIR}/${PROG}-${VERSION}.md5)

.include <bsd.prog.mk> 
