# $Id: Makefile,v 1.2 2007/04/14 06:25:57 mbalmer Exp $

PROG=		tablec
SRCS=		tablec.c

CFLAGS+= 	-Wall -I{.CURDIR}

LINTFLAGS+=	-u

MAN=		tablec.8
MANDIR=		/usr/local/man/cat

BINOWN = 	root
BINMOD =	0555
BINDIR= 	/usr/local/sbin

.include <bsd.prog.mk> 
