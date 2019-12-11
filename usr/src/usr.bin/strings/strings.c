/*
 * Copyright (c) 1980, 1987 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
char copyright[] =
"@(#) Copyright (c) 1980, 1987 The Regents of the University of California.\n\
 All rights reserved.\n";
#endif /* not lint */

#ifndef lint
/*static char sccsid[] = "from: @(#)strings.c	5.10 (Berkeley) 5/23/91";*/
static char rcsid[] = "$Id: strings.c,v 1.4 1993/11/13 01:51:02 jtc Exp $";
#endif /* not lint */

#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <a.out.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>

enum offset_radix {			/* radix used for string offset */
	OFFSET_NONE,
	OFFSET_OCT,
	OFFSET_DEC,
	OFFSET_HEX
} ;

#define DEF_LEN		4		/* default minimum string length */
#define ISSTR(ch)	(isascii(ch) && (isprint(ch) || ch == '\t'))

typedef struct exec	EXEC;		/* struct exec cast */

static long	foff;			/* offset in the file */
static int	hcnt,			/* head count */
		head_len,		/* length of header */
		read_len;		/* length to read */
static u_char	hbfr[sizeof(EXEC)];	/* buffer for struct exec */

static void usage();

main(argc, argv)
	int argc;
	char **argv;
{
	extern char *optarg;
	extern int optind;
	register int ch, cnt;
	register u_char *C;
	EXEC *head;
	int exitcode, minlen;
	short asdata, fflg;
	enum offset_radix oflg;
	u_char *bfr;
	char *file, *p;

	setlocale(LC_ALL, "");

	/*
	 * for backward compatibility, allow '-' to specify 'a' flag; no
	 * longer documented in the man page or usage string.
	 */
	asdata = exitcode = fflg = 0;
	oflg = OFFSET_NONE;
	minlen = -1;
	while ((ch = getopt(argc, argv, "-0123456789an:oft:")) != -1)
		switch((char)ch) {
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			/*
			 * kludge: strings was originally designed to take
			 * a number after a dash.
			 */
			if (minlen == -1) {
				p = argv[optind - 1];
				if (p[0] == '-' && p[1] == ch && !p[2])
					minlen = atoi(++p);
				else
					minlen = atoi(argv[optind] + 1);
			}
			break;
		case '-':
		case 'a':
			asdata = 1;
			break;
		case 'f':
			fflg = 1;
			break;
		case 'n':
			minlen = atoi(optarg);
			break;
		case 'o':
			oflg = OFFSET_OCT;
			break;
		case 't':
			switch (*optarg) {
			case 'o':
				oflg = OFFSET_OCT;
				break;
			case 'd':
				oflg = OFFSET_DEC;
				break;
			case 'x':
				oflg = OFFSET_HEX;
				break;
			default:
				usage();
				/* NOTREACHED */
			}
			break;
		case '?':
		default:
			usage();
		}
	argc -= optind;
	argv += optind;

	if (minlen == -1)
		minlen = DEF_LEN;

	if (!(bfr = malloc((u_int)minlen))) {
		(void)fprintf(stderr, "strings: %s\n", strerror(errno));
		exit(1);
	}
	bfr[minlen] = '\0';
	file = "stdin";
	do {
		if (*argv) {
			file = *argv++;
			if (!freopen(file, "r", stdin)) {
				(void)fprintf(stderr,
				    "strings: %s: %s\n", file, strerror(errno));
				exitcode = 1;
				goto nextfile;
			}
		}
		foff = 0;
#define DO_EVERYTHING()		{read_len = -1; head_len = 0; goto start;}
		read_len = -1;
		if (asdata)
			DO_EVERYTHING()
		else {
			head = (EXEC *)hbfr;
			if ((head_len =
			    read(fileno(stdin), head, sizeof(EXEC))) == -1)
				DO_EVERYTHING()
			if (head_len == sizeof(EXEC) && !N_BADMAG(*head)) {
				foff = N_TXTOFF(*head);
				if (fseek(stdin, foff, SEEK_SET) == -1)
					DO_EVERYTHING()
				read_len = head->a_text + head->a_data;
				head_len = 0;
			}
			else
				hcnt = 0;
		}
start:
		for (cnt = 0; (ch = getch()) != EOF;) {
			if (ISSTR(ch)) {
				if (!cnt)
					C = bfr;
				*C++ = ch;
				if (++cnt < minlen)
					continue;

				if (fflg)
					printf("%s:", file);
				switch (oflg) {
				case OFFSET_OCT:
					printf("%07lo ", foff - minlen);
					break;
				case OFFSET_DEC:
					printf("%07ld ", foff - minlen);
					break;
				case OFFSET_HEX:
					printf("%07lx ", foff - minlen);
					break;
				}
				printf("%s", bfr);

				while ((ch = getch()) != EOF && ISSTR(ch))
					putchar((char)ch);
				putchar('\n');
			}
			cnt = 0;
		}
nextfile: ;
	} while (*argv);
	exit(exitcode);
}

/*
 * getch --
 *	get next character from wherever
 */
getch()
{
	++foff;
	if (head_len) {
		if (hcnt < head_len)
			return((int)hbfr[hcnt++]);
		head_len = 0;
	}
	if (read_len == -1 || read_len-- > 0)
		return(getchar());
	return(EOF);
}

static void
usage()
{
	(void)fprintf(stderr,
	    "usage: strings [-afo] [-n length] [-t {o,d,x}] [file ... ]\n");
	exit(1);
}
