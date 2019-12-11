/*
 *                     RCS stream editor
 */
/**********************************************************************************
 *                       edits the input file according to a
 *                       script from stdin, generated by diff -n
 *                       performs keyword expansion
 **********************************************************************************
 */

/* Copyright (C) 1982, 1988, 1989 Walter Tichy
   Copyright 1990, 1991 by Paul Eggert
   Distributed under license by the Free Software Foundation, Inc.

This file is part of RCS.

RCS is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

RCS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with RCS; see the file COPYING.  If not, write to
the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

Report problems and direct all questions to:

    rcs-bugs@cs.purdue.edu

*/

#include "rcsbase.h"

libId(editId, "$Id: rcsedit.c,v 1.3.2.1 1994/10/11 10:20:37 mycroft Exp $")

static void keyreplace P((enum markers,struct hshentry const*,FILE*));


FILE *fcopy;		 /* result file descriptor			    */
char const *resultfile;  /* result file name				    */
int locker_expansion;	 /* should the locker name be appended to Id val?   */
#if !large_memory
	static RILE *fedit; /* edit file descriptor */
	static char const *editfile; /* edit pathname */
#endif
static unsigned long editline; /* edit line counter; #lines before cursor   */
static long linecorr; /* #adds - #deletes in each edit run.		    */
               /*used to correct editline in case file is not rewound after */
               /* applying one delta                                        */

#define DIRTEMPNAMES 2
enum maker {notmade, real, effective};
struct buf dirtfname[DIRTEMPNAMES];		/* unlink these when done */
static enum maker volatile dirtfmaker[DIRTEMPNAMES];	/* if these are set */


#if has_NFS || bad_unlink
	int
un_link(s)
	char const *s;
/*
 * Remove S, even if it is unwritable.
 * Ignore unlink() ENOENT failures; NFS generates bogus ones.
 */
{
#	if bad_unlink
		int e;
		if (unlink(s) == 0)
			return 0;
		e = errno;
#		if has_NFS
			if (e == ENOENT)
				return 0;
#		endif
		if (chmod(s, S_IWUSR) != 0) {
			errno = e;
			return -1;
		}
#	endif
#	if has_NFS
		return unlink(s)==0 || errno==ENOENT  ?  0  :  -1;
#	else
		return unlink(s);
#	endif
}
#endif

#if !has_rename
#  if !has_NFS
#	define do_link(s,t) link(s,t)
#  else
	static int
do_link(s, t)
	char const *s, *t;
/* Link S to T, ignoring bogus EEXIST problems due to NFS failures.  */
{
	struct stat sb, tb;

	if (link(s,t) == 0)
		return 0;
	if (errno != EEXIST)
		return -1;
	if (
	    stat(s, &sb) == 0  &&
	    stat(t, &tb) == 0  &&
	    sb.st_ino == tb.st_ino  &&
	    sb.st_dev == tb.st_dev
	)
		return 0;
	errno = EEXIST;
	return -1;
}
#  endif
#endif


	static exiting void
editEndsPrematurely()
{
	fatserror("edit script ends prematurely");
}

	static exiting void
editLineNumberOverflow()
{
	fatserror("edit script refers to line past end of file");
}


#if large_memory

#if has_memmove
#	define movelines(s1, s2, n) VOID memmove(s1, s2, (n)*sizeof(Iptr_type))
#else
	static void
movelines(s1, s2, n)
	register Iptr_type *s1;
	register Iptr_type const *s2;
	register unsigned long n;
{
	if (s1 < s2)
		do {
			*s1++ = *s2++;
		} while (--n);
	else {
		s1 += n;
		s2 += n;
		do {
			*--s1 = *--s2;
		} while (--n);
	}
}
#endif

/*
 * `line' contains pointers to the lines in the currently `edited' file.
 * It is a 0-origin array that represents linelim-gapsize lines.
 * line[0..gap-1] and line[gap+gapsize..linelim-1] contain pointers to lines.
 * line[gap..gap+gapsize-1] contains garbage.
 *
 * Any @s in lines are duplicated.
 * Lines are terminated by \n, or (for a last partial line only) by single @.
 */
static Iptr_type *line;
static unsigned long gap, gapsize, linelim;


	static void
insertline(n, l)
	unsigned long n;
	Iptr_type l;
/* Before line N, insert line L.  N is 0-origin.  */
{
	if (linelim-gapsize < n)
	    editLineNumberOverflow();
	if (!gapsize)
	    line =
		!linelim ?
			tnalloc(Iptr_type, linelim = gapsize = 1024)
		: (
			gap = gapsize = linelim,
			trealloc(Iptr_type, line, linelim <<= 1)
		);
	if (n < gap)
	    movelines(line+n+gapsize, line+n, gap-n);
	else if (gap < n)
	    movelines(line+gap, line+gap+gapsize, n-gap);

	line[n] = l;
	gap = n + 1;
	gapsize--;
}

	static void
deletelines(n, nlines)
	unsigned long n, nlines;
/* Delete lines N through N+NLINES-1.  N is 0-origin.  */
{
	unsigned long l = n + nlines;
	if (linelim-gapsize < l  ||  l < n)
	    editLineNumberOverflow();
	if (l < gap)
	    movelines(line+l+gapsize, line+l, gap-l);
	else if (gap < n)
	    movelines(line+gap, line+gap+gapsize, n-gap);

	gap = n;
	gapsize += nlines;
}

	static void
snapshotline(f, l)
	register FILE *f;
	register Iptr_type l;
{
	register int c;
	do {
		if ((c = *l++) == SDELIM  &&  *l++ != SDELIM)
			return;
		aputc(c, f);
	} while (c != '\n');
}

	void
snapshotedit(f)
	FILE *f;
/* Copy the current state of the edits to F.  */
{
	register Iptr_type *p, *lim, *l=line;
	for (p=l, lim=l+gap;  p<lim;  )
		snapshotline(f, *p++);
	for (p+=gapsize, lim=l+linelim;  p<lim;  )
		snapshotline(f, *p++);
}

	static void
finisheditline(fin, fout, l, delta)
	RILE *fin;
	FILE *fout;
	Iptr_type l;
	struct hshentry const *delta;
{
	Iseek(fin, l);
	if (expandline(fin, fout, delta, true, (FILE*)0)  <  0)
		faterror("finisheditline internal error");
}

	void
finishedit(delta, outfile, done)
	struct hshentry const *delta;
	FILE *outfile;
	int done;
/*
 * Doing expansion if DELTA is set, output the state of the edits to OUTFILE.
 * But do nothing unless DONE is set (which means we are on the last pass).
 */
{
	if (done) {
		openfcopy(outfile);
		outfile = fcopy;
		if (!delta)
			snapshotedit(outfile);
		else {
			register Iptr_type *p, *lim, *l = line;
			register RILE *fin = finptr;
			Iptr_type here = Itell(fin);
			for (p=l, lim=l+gap;  p<lim;  )
				finisheditline(fin, outfile, *p++, delta);
			for (p+=gapsize, lim=l+linelim;  p<lim;  )
				finisheditline(fin, outfile, *p++, delta);
			Iseek(fin, here);
		}
	}
}

/* Open a temporary FILENAME for output, truncating any previous contents.  */
#   define fopen_update_truncate(filename) fopen(filename, FOPEN_W_WORK)
#else /* !large_memory */
    static FILE *
fopen_update_truncate(filename)
    char const *filename;
{
#	if bad_fopen_wplus
		if (un_link(filename) != 0)
			efaterror(filename);
#	endif
	return fopen(filename, FOPEN_WPLUS_WORK);
}
#endif


	void
openfcopy(f)
	FILE *f;
{
	if (!(fcopy = f)) {
		if (!resultfile)
			resultfile = maketemp(2);
		if (!(fcopy = fopen_update_truncate(resultfile)))
			efaterror(resultfile);
	}
}


#if !large_memory

	static void
swapeditfiles(outfile)
	FILE *outfile;
/* Function: swaps resultfile and editfile, assigns fedit=fcopy,
 * and rewinds fedit for reading.  Set fcopy to outfile if nonnull;
 * otherwise, set fcopy to be resultfile opened for reading and writing.
 */
{
	char const *tmpptr;

	editline = 0;  linecorr = 0;
	if (fseek(fcopy, 0L, SEEK_SET) != 0)
		Oerror();
	fedit = fcopy;
        tmpptr=editfile; editfile=resultfile; resultfile=tmpptr;
	openfcopy(outfile);
}

	void
snapshotedit(f)
	FILE *f;
/* Copy the current state of the edits to F.  */
{
	finishedit((struct hshentry *)nil, (FILE*)0, false);
	fastcopy(fedit, f);
	Irewind(fedit);
}

	void
finishedit(delta, outfile, done)
	struct hshentry const *delta;
	FILE *outfile;
	int done;
/* copy the rest of the edit file and close it (if it exists).
 * if delta!=nil, perform keyword substitution at the same time.
 * If DONE is set, we are finishing the last pass.
 */
{
	register RILE *fe;
	register FILE *fc;

	fe = fedit;
	if (fe) {
		fc = fcopy;
                if (delta!=nil) {
			while (1 < expandline(fe,fc,delta,false,(FILE*)0))
				;
                } else {
			fastcopy(fe,fc);
                }
		Ifclose(fe);
        }
	if (!done)
		swapeditfiles(outfile);
}
#endif



#if large_memory
#	define copylines(upto,delta) (editline = (upto))
#else
	static void
copylines(upto,delta)
	register unsigned long upto;
	struct hshentry const *delta;
/*
 * Copy input lines editline+1..upto from fedit to fcopy.
 * If delta != nil, keyword expansion is done simultaneously.
 * editline is updated. Rewinds a file only if necessary.
 */
{
	register int c;
	declarecache;
	register FILE *fc;
	register RILE *fe;

	if (upto < editline) {
                /* swap files */
		finishedit((struct hshentry *)nil, (FILE*)0, false);
                /* assumes edit only during last pass, from the beginning*/
        }
	fe = fedit;
	fc = fcopy;
	if (editline < upto)
	    if (delta)
		do {
			if (expandline(fe,fc,delta,false,(FILE*)0) <= 1)
				editLineNumberOverflow();
		} while (++editline < upto);
	    else {
		setupcache(fe); cache(fe);
		do {
			do {
				cachegeteof(c, editLineNumberOverflow(););
				aputc(c, fc);
			} while (c != '\n');
		} while (++editline < upto);
		uncache(fe);
	    }
}
#endif



	void
xpandstring(delta)
	struct hshentry const *delta;
/* Function: Reads a string terminated by SDELIM from finptr and writes it
 * to fcopy. Double SDELIM is replaced with single SDELIM.
 * Keyword expansion is performed with data from delta.
 * If foutptr is nonnull, the string is also copied unchanged to foutptr.
 */
{
	while (1 < expandline(finptr,fcopy,delta,true,foutptr))
		;
}


	void
copystring()
/* Function: copies a string terminated with a single SDELIM from finptr to
 * fcopy, replacing all double SDELIM with a single SDELIM.
 * If foutptr is nonnull, the string also copied unchanged to foutptr.
 * editline is incremented by the number of lines copied.
 * Assumption: next character read is first string character.
 */
{	register c;
	declarecache;
	register FILE *frew, *fcop;
	register int amidline;
	register RILE *fin;

	fin = finptr;
	setupcache(fin); cache(fin);
	frew = foutptr;
	fcop = fcopy;
	amidline = false;
	for (;;) {
		GETC(frew,c);
		switch (c) {
		    case '\n':
			++editline;
			++rcsline;
			amidline = false;
			break;
		    case SDELIM:
			GETC(frew,c);
			if (c != SDELIM) {
				/* end of string */
				nextc = c;
				editline += amidline;
				uncache(fin);
				return;
			}
			/* fall into */
		    default:
			amidline = true;
			break;
                }
		aputc(c,fcop);
        }
}


	void
enterstring()
/* Like copystring, except the string is put into the edit data structure.  */
{
#if !large_memory
	editfile = 0;
	fedit = 0;
	editline = linecorr = 0;
	resultfile = maketemp(1);
	if (!(fcopy = fopen_update_truncate(resultfile)))
		efaterror(resultfile);
	copystring();
#else
	register int c;
	declarecache;
	register FILE *frew;
	register unsigned long e, oe;
	register int amidline, oamidline;
	register Iptr_type optr;
	register RILE *fin;

	e = 0;
	gap = 0;
	gapsize = linelim;
	fin = finptr;
	setupcache(fin); cache(fin);
	advise_access(fin, MADV_NORMAL);
	frew = foutptr;
	amidline = false;
	for (;;) {
		optr = cachetell();
		GETC(frew,c);
		oamidline = amidline;
		oe = e;
		switch (c) {
		    case '\n':
			++e;
			++rcsline;
			amidline = false;
			break;
		    case SDELIM:
			GETC(frew,c);
			if (c != SDELIM) {
				/* end of string */
				nextc = c;
				editline = e + amidline;
				linecorr = 0;
				uncache(fin);
				return;
			}
			/* fall into */
		    default:
			amidline = true;
			break;
		}
		if (!oamidline)
			insertline(oe, optr);
	}
#endif
}




	void
#if large_memory
edit_string()
#else
  editstring(delta)
	struct hshentry const *delta;
#endif
/*
 * Read an edit script from finptr and applies it to the edit file.
#if !large_memory
 * The result is written to fcopy.
 * If delta!=nil, keyword expansion is performed simultaneously.
 * If running out of lines in fedit, fedit and fcopy are swapped.
 * editfile is the name of the file that goes with fedit.
#endif
 * If foutptr is set, the edit script is also copied verbatim to foutptr.
 * Assumes that all these files are open.
 * resultfile is the name of the file that goes with fcopy.
 * Assumes the next input character from finptr is the first character of
 * the edit script. Resets nextc on exit.
 */
{
        int ed; /* editor command */
        register int c;
	declarecache;
	register FILE *frew;
#	if !large_memory
		register FILE *f;
		unsigned long line_lim = ULONG_MAX;
		register RILE *fe;
#	endif
	register unsigned long i;
	register RILE *fin;
#	if large_memory
		register unsigned long j;
#	endif
	struct diffcmd dc;

        editline += linecorr; linecorr=0; /*correct line number*/
	frew = foutptr;
	fin = finptr;
	setupcache(fin);
	initdiffcmd(&dc);
	while (0  <=  (ed = getdiffcmd(fin,true,frew,&dc)))
#if !large_memory
		if (line_lim <= dc.line1)
			editLineNumberOverflow();
		else
#endif
		if (!ed) {
			copylines(dc.line1-1, delta);
                        /* skip over unwanted lines */
			i = dc.nlines;
			linecorr -= i;
			editline += i;
#			if large_memory
			    deletelines(editline+linecorr, i);
#			else
			    fe = fedit;
			    do {
                                /*skip next line*/
				do {
				    Igeteof(fe, c, { if (i!=1) editLineNumberOverflow(); line_lim = dc.dafter; break; } );
				} while (c != '\n');
			    } while (--i);
#			endif
		} else {
			copylines(dc.line1, delta); /*copy only; no delete*/
			i = dc.nlines;
#			if large_memory
				j = editline+linecorr;
#			endif
			linecorr += i;
#if !large_memory
			f = fcopy;
			if (delta)
			    do {
				switch (expandline(fin,f,delta,true,frew)) {
				    case 0: case 1:
					if (i==1)
					    return;
					/* fall into */
				    case -1:
					editEndsPrematurely();
				}
			    } while (--i);
			else
#endif
			{
			    cache(fin);
			    do {
#				if large_memory
				    insertline(j++, cachetell());
#				endif
				for (;;) {
				    GETC(frew, c);
#				    if !large_memory
					aputc(c, f);
#				    endif
				    if (c == '\n')
					break;
				    if (c==SDELIM) {
					GETC(frew, c);
					if (c!=SDELIM) {
					    if (--i)
						editEndsPrematurely();
					    nextc = c;
					    uncache(fin);
					    return;
					}
				    }
				}
				++rcsline;
			    } while (--i);
			    uncache(fin);
			}
                }
}



/* The rest is for keyword expansion */



	int
expandline(infile, outfile, delta, delimstuffed, frewfile)
	RILE *infile;
	FILE *outfile, *frewfile;
	struct hshentry const *delta;
	int delimstuffed;
/*
 * Read a line from INFILE and write it to OUTFILE.
 * If DELIMSTUFFED is true, double SDELIM is replaced with single SDELIM.
 * Keyword expansion is performed with data from delta.
 * If FREWFILE is set, copy the line unchanged to FREWFILE.
 * DELIMSTUFFED must be true if FREWFILE is set.
 * Yields -1 if no data is copied, 0 if an incomplete line is copied,
 * 2 if a complete line is copied; adds 1 to yield if expansion occurred.
 */
{
	register c;
	declarecache;
	register FILE *out, *frew;
	register char * tp;
	register int e, ds, r;
	char const *tlim;
	static struct buf keyval;
        enum markers matchresult;

	setupcache(infile); cache(infile);
	out = outfile;
	frew = frewfile;
	ds = delimstuffed;
	bufalloc(&keyval, keylength+3);
	e = 0;
	r = -1;

        for (;;) {
	    if (ds) {
		GETC(frew, c);
	    } else
		cachegeteof(c, goto uncache_exit;);
	    for (;;) {
		switch (c) {
		    case SDELIM:
			if (ds) {
			    GETC(frew, c);
			    if (c != SDELIM) {
                                /* end of string */
                                nextc=c;
				goto uncache_exit;
			    }
			}
			/* fall into */
		    default:
			aputc(c,out);
			r = 0;
			break;

		    case '\n':
			rcsline += ds;
			aputc(c,out);
			r = 2;
			goto uncache_exit;

		    case KDELIM:
			r = 0;
                        /* check for keyword */
                        /* first, copy a long enough string into keystring */
			tp = keyval.string;
			*tp++ = KDELIM;
			for (;;) {
			    if (ds) {
				GETC(frew, c);
			    } else
				cachegeteof(c, goto keystring_eof;);
			    if (tp < keyval.string+keylength+1)
				switch (ctab[c]) {
				    case LETTER: case Letter:
					*tp++ = c;
					continue;
				    default:
					break;
				}
			    break;
                        }
			*tp++ = c; *tp = '\0';
			matchresult = trymatch(keyval.string+1);
			if (matchresult==Nomatch) {
				tp[-1] = 0;
				aputs(keyval.string, out);
				continue;   /* last c handled properly */
			}

			/* Now we have a keyword terminated with a K/VDELIM */
			if (c==VDELIM) {
			      /* try to find closing KDELIM, and replace value */
			      tlim = keyval.string + keyval.size;
			      for (;;) {
				      if (ds) {
					GETC(frew, c);
				      } else
					cachegeteof(c, goto keystring_eof;);
				      if (c=='\n' || c==KDELIM)
					break;
				      *tp++ =c;
				      if (tlim <= tp)
					  tp = bufenlarge(&keyval, &tlim);
				      if (c==SDELIM && ds) { /*skip next SDELIM */
						GETC(frew, c);
						if (c != SDELIM) {
							/* end of string before closing KDELIM or newline */
							nextc = c;
							goto keystring_eof;
						}
				      }
			      }
			      if (c!=KDELIM) {
				    /* couldn't find closing KDELIM -- give up */
				    *tp = 0;
				    aputs(keyval.string, out);
				    continue;   /* last c handled properly */
			      }
			}
			/* now put out the new keyword value */
			keyreplace(matchresult,delta,out);
			e = 1;
			break;
                }
		break;
	    }
        }

    keystring_eof:
	*tp = 0;
	aputs(keyval.string, out);
    uncache_exit:
	uncache(infile);
	return r + e;
}


char const ciklog[ciklogsize] = "checked in with -k by ";

	static void
keyreplace(marker,delta,out)
	enum markers marker;
	register struct hshentry const *delta;
	register FILE *out;
/* function: outputs the keyword value(s) corresponding to marker.
 * Attributes are derived from delta.
 */
{
	register char const *sp, *cp, *date;
	register char c;
	register size_t cs, cw, ls;
	char const *sp1;
	char datebuf[datesize];
	int RCSv;

	sp = Keyword[(int)marker];

	if (Expand == KEY_EXPAND) {
		aprintf(out, "%c%s%c", KDELIM, sp, KDELIM);
		return;
	}

        date= delta->date;
	RCSv = RCSversion;

	if (Expand == KEYVAL_EXPAND  ||  Expand == KEYVALLOCK_EXPAND)
		aprintf(out, "%c%s%c%c", KDELIM, sp, VDELIM,
			marker==Log && RCSv<VERSION(5)  ?  '\t'  :  ' '
		);

        switch (marker) {
        case Author:
		aputs(delta->author, out);
                break;
        case Date:
		aputs(date2str(date,datebuf), out);
                break;
	case Header:
        case Id:
#ifdef LOCALID
	case LocalId:
#endif
		aprintf(out, "%s %s %s %s %s",
			  marker!=Header || RCSv<VERSION(4)
			? basename(RCSfilename)
			: getfullRCSname(),
			delta->num,
			date2str(date, datebuf),
			delta->author,
			  RCSv==VERSION(3) && delta->lockedby ? "Locked"
			: delta->state
		);
		if (delta->lockedby!=nil)
		    if (VERSION(5) <= RCSv) {
			if (locker_expansion || Expand==KEYVALLOCK_EXPAND)
			    aprintf(out, " %s", delta->lockedby);
		    } else if (RCSv == VERSION(4))
			aprintf(out, " Locker: %s", delta->lockedby);
                break;
        case Locker:
		if (delta->lockedby)
		    if (
				locker_expansion
			||	Expand == KEYVALLOCK_EXPAND
			||	RCSv <= VERSION(4)
		    )
			aputs(delta->lockedby, out);
                break;
        case Log:
        case RCSfile:
		aputs(basename(RCSfilename), out);
                break;
        case Revision:
		aputs(delta->num, out);
                break;
        case Source:
		aputs(getfullRCSname(), out);
                break;
        case State:
		aputs(delta->state, out);
                break;
	default:
		break;
        }
	if (Expand == KEYVAL_EXPAND  ||  Expand == KEYVALLOCK_EXPAND) {
		afputc(' ', out);
		afputc(KDELIM, out);
	}
	if (marker == Log) {
		sp = delta->log.string;
		ls = delta->log.size;
		if (sizeof(ciklog)-1<=ls && !memcmp(sp,ciklog,sizeof(ciklog)-1))
			return;
		afputc('\n', out);
		cp = Comment.string;
		cw = cs = Comment.size;
		awrite(cp, cs, out);
		/* oddity: 2 spaces between date and time, not 1 as usual */
		sp1 = strchr(date2str(date,datebuf), ' ');
		aprintf(out, "Revision %s  %.*s %s  %s",
		    delta->num, (int)(sp1-datebuf), datebuf, sp1, delta->author
		);
		/* Do not include state: it may change and is not updated.  */
		/* Comment is the comment leader.  */
		if (VERSION(5) <= RCSv)
		    for (;  cw && (cp[cw-1]==' ' || cp[cw-1]=='\t');  --cw)
			;
		for (;;) {
		    afputc('\n', out);
		    awrite(cp, cw, out);
		    if (!ls)
			break;
		    --ls;
		    c = *sp++;
		    if (c != '\n') {
			awrite(cp+cw, cs-cw, out);
			do {
			    afputc(c,out);
			    if (!ls)
				break;
			    --ls;
			    c = *sp++;
			} while (c != '\n');
		    }
		}
	}
}

#if has_readlink
	static int
resolve_symlink(L)
	struct buf *L;
/*
 * If L is a symbolic link, resolve it to the name that it points to.
 * If unsuccessful, set errno and yield -1.
 * If it points to an existing file, yield 1.
 * Otherwise, set errno=ENOENT and yield 0.
 */
{
	char *b, a[SIZEABLE_PATH];
	int e;
	size_t s;
	ssize_t r;
	struct buf bigbuf;
	unsigned linkcount = MAXSYMLINKS + 1;

	b = a;
	s = sizeof(a);
	bufautobegin(&bigbuf);
	while ((r = readlink(L->string,b,s))  !=  -1)
	    if (r == s) {
		bufalloc(&bigbuf, s<<1);
		b = bigbuf.string;
		s = bigbuf.size;
	    } else if (!--linkcount) {
		errno = ELOOP;
		return -1;
	    } else {
		/* Splice symbolic link into L.  */
		b[r] = '\0';
		L->string[ROOTPATH(b) ? (size_t)0 : dirlen(L->string)]  =  '\0';
		bufscat(L, b);
	    }
	e = errno;
	bufautoend(&bigbuf);
	errno = e;
	switch (e) {
	    case ENXIO:
	    case EINVAL: return 1;
	    case ENOENT: return 0;
	    default: return -1;
	}
}
#endif

	RILE *
rcswriteopen(RCSbuf, status, mustread)
	struct buf *RCSbuf;
	struct stat *status;
	int mustread;
/*
 * Create the lock file corresponding to RCSNAME.
 * Then try to open RCSNAME for reading and yield its FILE* descriptor.
 * Put its status into *STATUS too.
 * MUSTREAD is true if the file must already exist, too.
 * If all goes well, discard any previously acquired locks,
 * and set frewrite to the FILE* descriptor of the lock file,
 * which will eventually turn into the new RCS file.
 */
{
	register char *tp;
	register char const *sp, *RCSname, *x;
	RILE *f;
	size_t l;
	int e, exists, fdesc, previouslock, r;
	struct buf *dirt;
	struct stat statbuf;

	previouslock  =  frewrite != 0;
	exists =
#		if has_readlink
			resolve_symlink(RCSbuf);
#		else
			    stat(RCSbuf->string, &statbuf) == 0  ?  1
			:   errno==ENOENT ? 0 : -1;
#		endif
	if (exists < (mustread|previouslock))
		/*
		 * There's an unusual problem with the RCS file;
		 * or the RCS file doesn't exist,
		 * and we must read or we already have a lock elsewhere.
		 */
		return 0;

	RCSname = RCSbuf->string;
	sp = basename(RCSname);
	l = sp - RCSname;
	dirt = &dirtfname[previouslock];
	bufscpy(dirt, RCSname);
	tp = dirt->string + l;
	x = rcssuffix(RCSname);
#	if has_readlink
	    if (!x) {
		error("symbolic link to non RCS filename `%s'", RCSname);
		errno = EINVAL;
		return 0;
	    }
#	endif
	if (*sp == *x) {
		error("RCS filename `%s' incompatible with suffix `%s'", sp, x);
		errno = EINVAL;
		return 0;
	}
	/* Create a lock file whose name is a function of the RCS filename.  */
	if (*x) {
		/*
		 * The suffix is nonempty.
		 * The lock filename is the first char of of the suffix,
		 * followed by the RCS filename with last char removed.  E.g.:
		 *	foo,v	RCS filename with suffix ,v
		 *	,foo,	lock filename
		 */
		*tp++ = *x;
		while (*sp)
			*tp++ = *sp++;
		*--tp = 0;
	} else {
		/*
		 * The suffix is empty.
		 * The lock filename is the RCS filename
		 * with last char replaced by '_'.
		 */
		while ((*tp++ = *sp++))
			;
		tp -= 2;
		if (*tp == '_') {
			error("RCS filename `%s' ends with `%c'", RCSname, *tp);
			errno = EINVAL;
			return 0;
		}
		*tp = '_';
	}

	sp = tp = dirt->string;

	f = 0;

	/*
	* good news:
	*	open(f, O_CREAT|O_EXCL|O_TRUNC|O_WRONLY, READONLY) is atomic
	*	according to Posix 1003.1-1990.
	* bad news:
	*	NFS ignores O_EXCL and doesn't comply with Posix 1003.1-1990.
	* good news:
	*	(O_TRUNC,READONLY) normally guarantees atomicity even with NFS.
	* bad news:
	*	If you're root, (O_TRUNC,READONLY) doesn't guarantee atomicity.
	* good news:
	*	Root-over-the-wire NFS access is rare for security reasons.
	*	This bug has never been reported in practice with RCS.
	* So we don't worry about this bug.
	*
	* An even rarer NFS bug can occur when clients retry requests.
	* Suppose client A renames the lock file ",f," to "f,v"
	* at about the same time that client B creates ",f,",
	* and suppose A's first rename request is delayed, so A reissues it.
	* The sequence of events might be:
	*	A sends rename(",f,", "f,v")
	*	B sends create(",f,")
	*	A sends retry of rename(",f,", "f,v")
	*	server receives, does, and acknowledges A's first rename()
	*	A receives acknowledgment, and its RCS program exits
	*	server receives, does, and acknowledges B's create()
	*	server receives, does, and acknowledges A's retry of rename()
	* This not only wrongly deletes B's lock, it removes the RCS file!
	* Most NFS implementations have idempotency caches that usually prevent
	* this scenario, but such caches are finite and can be overrun.
	* This problem afflicts programs that use the traditional
	* Unix method of using link() and unlink() to get and release locks,
	* as well as RCS's method of using open() and rename().
	* There is no easy workaround for either link-unlink or open-rename.
	* Any new method based on lockf() seemingly would be incompatible with
	* the old methods; besides, lockf() is notoriously buggy under NFS.
	* Since this problem afflicts scads of Unix programs, but is so rare
	* that nobody seems to be worried about it, we won't worry either.
	*/
#	define READONLY (S_IRUSR|S_IRGRP|S_IROTH)
#	if !open_can_creat
#		define create(f) creat(f, READONLY)
#	else
#		define create(f) open(f, O_BINARY|O_CREAT|O_EXCL|O_TRUNC|O_WRONLY, READONLY)
#	endif

	catchints();
	ignoreints();

	/*
	 * Create a lock file for an RCS file.  This should be atomic, i.e.
	 * if two processes try it simultaneously, at most one should succeed.
	 */
	seteid();
	fdesc = create(sp);
	e = errno;
	setrid();

	if (fdesc < 0) {
		if (e == EACCES  &&  stat(tp,&statbuf) == 0)
			/* The RCS file is busy.  */
			e = EEXIST;
	} else {
		dirtfmaker[0] = effective;
		e = ENOENT;
		if (exists) {
		    f = Iopen(RCSname, FOPEN_R, status);
		    e = errno;
		    if (f && previouslock) {
			/* Discard the previous lock in favor of this one.  */
			Ozclose(&frewrite);
			seteid();
			if ((r = un_link(newRCSfilename)) != 0)
			    e = errno;
			setrid();
			if (r != 0)
			    enfaterror(e, newRCSfilename);
			bufscpy(&dirtfname[0], tp);
		    }
		}
		if (!(frewrite = fdopen(fdesc, FOPEN_W))) {
		    efaterror(newRCSfilename);
		}
	}

	restoreints();

	errno = e;
	return f;
}

	void
keepdirtemp(name)
	char const *name;
/* Do not unlink name, either because it's not there any more,
 * or because it has already been unlinked.
 */
{
	register int i;
	for (i=DIRTEMPNAMES; 0<=--i; )
		if (dirtfname[i].string == name) {
			dirtfmaker[i] = notmade;
			return;
		}
	faterror("keepdirtemp");
}

	char const *
makedirtemp(name, n)
	register char const *name;
	int n;
/*
 * Have maketemp() do all the work if name is null.
 * Otherwise, create a unique filename in name's dir using n and name
 * and store it into the dirtfname[n].
 * Because of storage in tfnames, dirtempunlink() can unlink the file later.
 * Return a pointer to the filename created.
 */
{
	register char *tp, *np;
	register size_t dl;
	register struct buf *bn;

	if (!name)
		return maketemp(n);
	dl = dirlen(name);
	bn = &dirtfname[n];
	bufalloc(bn,
#		if has_mktemp
			dl + 9
#		else
			strlen(name) + 3
#		endif
	);
	bufscpy(bn, name);
	np = tp = bn->string;
	tp += dl;
	*tp++ = '_';
	*tp++ = '0'+n;
	catchints();
#	if has_mktemp
		VOID strcpy(tp, "XXXXXX");
		if (!mktemp(np) || !*np)
		    faterror("can't make temporary file name `%.*s%c_%cXXXXXX'",
			(int)dl, name, SLASH, '0'+n
		    );
#	else
		/*
		 * Posix 1003.1-1990 has no reliable way
		 * to create a unique file in a named directory.
		 * We fudge here.  If the working file name is abcde,
		 * the temp filename is _Ncde where N is a digit.
		 */
		name += dl;
		if (*name) name++;
		if (*name) name++;
		VOID strcpy(tp, name);
#	endif
	dirtfmaker[n] = real;
	return np;
}

	void
dirtempunlink()
/* Clean up makedirtemp() files.  May be invoked by signal handler. */
{
	register int i;
	enum maker m;

	for (i = DIRTEMPNAMES;  0 <= --i;  )
	    if ((m = dirtfmaker[i]) != notmade) {
		if (m == effective)
		    seteid();
		VOID un_link(dirtfname[i].string);
		if (m == effective)
		    setrid();
		dirtfmaker[i] = notmade;
	    }
}


	int
#if has_prototypes
chnamemod(FILE **fromp, char const *from, char const *to, mode_t mode)
  /* The `#if has_prototypes' is needed because mode_t might promote to int.  */
#else
  chnamemod(fromp,from,to,mode) FILE **fromp; char const *from,*to; mode_t mode;
#endif
/*
 * Rename a file (with optional stream pointer *FROMP) from FROM to TO.
 * FROM already exists.
 * Change its mode to MODE, before renaming if possible.
 * If FROMP, close and clear *FROMP before renaming it.
 * Unlink TO if it already exists.
 * Return -1 on error (setting errno), 0 otherwise.
 */
{
#	if bad_a_rename
		/*
		 * This host is brain damaged.  A race condition is possible
		 * while the lock file is temporarily writable.
		 * There doesn't seem to be a workaround.
		 */
		mode_t mode_while_renaming = mode|S_IWUSR;
#	else
#		define mode_while_renaming mode
#	endif
	if (fromp) {
#		if has_fchmod
			if (fchmod(fileno(*fromp), mode_while_renaming) != 0)
				return -1;
#		endif
		Ozclose(fromp);
	}
#	if has_fchmod
	    else
#	endif
	    if (chmod(from, mode_while_renaming) != 0)
		return -1;

#	if !has_rename || bad_b_rename
		VOID un_link(to);
		/*
		 * We need not check the result;
		 * link() or rename() will catch it.
		 * No harm is done if TO does not exist.
		 * However, there's a short window of inconsistency
		 * during which TO does not exist.
		 */
#	endif

	return
#	    if !has_rename
		do_link(from,to) != 0  ?  -1  :  un_link(from)
#	    else
		    rename(from, to) != 0
#		    if has_NFS
			&& errno != ENOENT
#		    endif
		?  -1
#		if bad_a_rename
		:  mode != mode_while_renaming  ?  chmod(to, mode)
#		endif
		:  0
#	    endif
	;

#	undef mode_while_renaming
}



	int
findlock(delete, target)
	int delete;
	struct hshentry **target;
/*
 * Find the first lock held by caller and return a pointer
 * to the locked delta; also removes the lock if DELETE.
 * If one lock, put it into *TARGET.
 * Return 0 for no locks, 1 for one, 2 for two or more.
 */
{
	register struct lock *next, **trail, **found;

	found = 0;
	for (trail = &Locks;  (next = *trail);  trail = &next->nextlock)
		if (strcmp(getcaller(), next->login)  ==  0) {
			if (found) {
				error("multiple revisions locked by %s; please specify one", getcaller());
				return 2;
			}
			found = trail;
		}
	if (!found)
		return 0;
	next = *found;
	*target = next->delta;
	if (delete) {
		next->delta->lockedby = nil;
		*found = next->nextlock;
	}
	return 1;
}

	int
addlock(delta)
	struct hshentry * delta;
/*
 * Add a lock held by caller to DELTA and yield 1 if successful.
 * Print an error message and yield -1 if no lock is added because
 * DELTA is locked by somebody other than caller.
 * Return 0 if the caller already holds the lock.
 */
{
	register struct lock *next;

	next=Locks;
	for (next = Locks;  next;  next = next->nextlock)
		if (cmpnum(delta->num, next->delta->num) == 0)
			if (strcmp(getcaller(), next->login) == 0)
				return 0;
			else {
				error("revision %s already locked by %s",
				      delta->num, next->login
				);
				return -1;
			}
	next = ftalloc(struct lock);
	delta->lockedby = next->login = getcaller();
	next->delta = delta;
	next->nextlock = Locks;
	Locks = next;
	return 1;
}


	int
addsymbol(num, name, rebind)
	char const *num, *name;
	int rebind;
/*
 * Associate with revision NUM the new symbolic NAME.
 * If NAME already exists and REBIND is set, associate NAME with NUM;
 * otherwise, print an error message and return false;
 * Return true if successful.
 */
{
	register struct assoc *next;

	for (next = Symbols;  next;  next = next->nextassoc)
		if (strcmp(name, next->symbol)  ==  0)
			if (rebind  ||  strcmp(next->num,num) == 0) {
				next->num = num;
				return true;
			} else {
				error("symbolic name %s already bound to %s",
					name, next->num
				);
				return false;
			}
	next = ftalloc(struct assoc);
	next->symbol = name;
	next->num = num;
	next->nextassoc = Symbols;
	Symbols = next;
	return true;
}



	char const *
getcaller()
/* Get the caller's login name.  */
{
#	if has_setuid
		return getusername(euid()!=ruid());
#	else
		return getusername(false);
#	endif
}


	int
checkaccesslist()
/*
 * Return true if caller is the superuser, the owner of the
 * file, the access list is empty, or caller is on the access list.
 * Otherwise, print an error message and return false.
 */
{
	register struct access const *next;

	if (!AccessList || myself(RCSstat.st_uid) || strcmp(getcaller(),"root")==0)
		return true;

	next = AccessList;
	do {
		if (strcmp(getcaller(), next->login)  ==  0)
			return true;
	} while ((next = next->nextaccess));

	error("user %s not on the access list", getcaller());
	return false;
}


	int
dorewrite(lockflag, changed)
	int lockflag, changed;
/*
 * Do nothing if LOCKFLAG is zero.
 * Prepare to rewrite an RCS file if CHANGED is positive.
 * Stop rewriting if CHANGED is zero, because there won't be any changes.
 * Fail if CHANGED is negative.
 * Return true on success.
 */
{
	int r, e;

	if (lockflag)
		if (changed) {
			if (changed < 0)
				return false;
			putadmin(frewrite);
			puttree(Head, frewrite);
			aprintf(frewrite, "\n\n%s%c", Kdesc, nextc);
			foutptr = frewrite;
		} else {
			Ozclose(&frewrite);
			seteid();
			ignoreints();
			r = un_link(newRCSfilename);
			e = errno;
			keepdirtemp(newRCSfilename);
			restoreints();
			setrid();
			if (r != 0) {
				enerror(e, RCSfilename);
				return false;
			}
		}
	return true;
}

	int
donerewrite(changed)
	int changed;
/*
 * Finish rewriting an RCS file if CHANGED is nonzero.
 * Return true on success.
 */
{
	int r, e;

	if (changed && !nerror) {
		if (finptr) {
			fastcopy(finptr, frewrite);
			Izclose(&finptr);
		}
		if (1 < RCSstat.st_nlink)
			warn("breaking hard link to %s", RCSfilename);
		seteid();
		ignoreints();
		r = chnamemod(&frewrite, newRCSfilename, RCSfilename,
			RCSstat.st_mode & ~(S_IWUSR|S_IWGRP|S_IWOTH)
		);
		e = errno;
		keepdirtemp(newRCSfilename);
		restoreints();
		setrid();
		if (r != 0) {
			enerror(e, RCSfilename);
			error("saved in %s", newRCSfilename);
			dirtempunlink();
			return false;
		}
	}
	return true;
}

	void
aflush(f)
	FILE *f;
{
	if (fflush(f) != 0)
		Oerror();
}
