%{
/*	$Id: scan.l,v 1.2 2007/04/04 12:38:18 dhartmei Exp $ */

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

#include <string.h>

#include "y.tab.h"

%}

%option yylineno noyywrap nounput

%%

[ \t]+			/* ignore whitespace */ ;

socket			{ return SOCKET; }
listen			{ return LISTEN; }
secret			{ return SECRET; }
log-facility		{ return LOGFAC; }

local0			{ return LOCAL0; }
local1			{ return LOCAL1; }
local2			{ return LOCAL2; }
local3			{ return LOCAL3; }
local4			{ return LOCAL4; }
local5			{ return LOCAL5; }
local6			{ return LOCAL6; }
local7			{ return LOCAL7; }
daemon			{ return DAEMON;}
mail			{ return MAIL; }

[0-9]+			{ yylval.string = strdup(yytext); return NUMBER; }

#.*\n			/* ignore comments */ ;

[a-zA-Z0-9_\-:\.,/\*]+	{ yylval.string = strdup(yytext); return TEXT; }

\"([^"\n]*)["\n]	{
				yytext[yyleng - 1] = 0;
				yyleng -= 2;
				yylval.string = strdup(yytext + 1);
				return TEXT;
			}

=			{ return '='; }

\n			{ return '\n'; }
