%{
/*	$Id: parse.y,v 1.3 2007/04/04 12:38:18 dhartmei Exp $	*/

/*
 * Copyright (c) 2006, 2007 Marc Balmer <marc@msys.ch>
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
#include <sys/time.h>
#include <sys/resource.h>

#include <ctype.h>
#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "tabled.h"

extern FILE	*yyin;
extern int	 yylineno;
extern char	*yytext;

extern char	*sock;
extern char	*listen_addr;
extern char	*secret;
extern int	 log_facility;
extern char	*cfgfile;

extern int pftable_exists(const char *);

int	yyerror(const char *, ...);
int	yyparse(void);
int	yylex(void);

static int 	 yyerrcnt;

%}

%union {
	long	 number;
	char	*string;
}

%token	SOCKET LISTEN SECRET LOGFAC
%token	LOCAL0 LOCAL1 LOCAL2 LOCAL3
%token	LOCAL4 LOCAL5 LOCAL6 LOCAL7
%token	DAEMON MAIL USER
%token	<string>	NUMBER
%token	<string>	TEXT
%type	<number>	logfac

%%
statement	: /* empty */
		| statement '\n'
		| statement socket '\n'
		| statement logfacility '\n'
		| statement listen '\n'
		| statement secret '\n'
		;

socket		: SOCKET '=' TEXT				{
			if (sock == NULL)
				sock = $3;
			else
				free($3);
		}
		;

logfacility	:	LOGFAC '=' logfac	{
				log_facility = $3;
		}
		;

logfac		:	LOCAL0		{ $$ = LOG_LOCAL0; }
		|	LOCAL1		{ $$ = LOG_LOCAL1; }
		|	LOCAL2		{ $$ = LOG_LOCAL2; }
		|	LOCAL3		{ $$ = LOG_LOCAL3; }
		|	LOCAL4		{ $$ = LOG_LOCAL4; }
		|	LOCAL5		{ $$ = LOG_LOCAL5; }
		|	LOCAL6		{ $$ = LOG_LOCAL6; }
		|	LOCAL7		{ $$ = LOG_LOCAL7; }
		|	DAEMON		{ $$ = LOG_DAEMON; }
		|	MAIL		{ $$ = LOG_MAIL; }
		|	USER		{ $$ = LOG_USER; }
		;

listen		: LISTEN '=' TEXT				{
			if (listen_addr == NULL)
				listen_addr = $3;
			else
				free($3);
		}
		;

secret		: SECRET '=' TEXT				{
			if (secret == NULL)
				secret = $3;
			else
				free($3);
		}
		;

%%

void
tabled_init(void)
{
	yylineno = 1;
	yyerrcnt = 0;
	if ((yyin = fopen(cfgfile, "r")) != NULL) {
		while (!feof(yyin))
			yyparse();

		fclose(yyin);
	}
	if (yyerrcnt)
		errx(1, "configuration file contains errors, terminating");
}

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;
	char		*nfmt;

	++yyerrcnt;
	va_start(ap, fmt);
	if (asprintf(&nfmt, "%s, line %d: %s near '%s'",
	    cfgfile, yylineno, fmt, yytext) == -1)
		errx(1, "asprintf failed");
	fprintf(stderr, "%s\n", nfmt);
	va_end(ap);
	free(nfmt);
	return 0;
}
