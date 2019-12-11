/*
 * Copyright (c) 1993 Adam Glass 
 * Copyright (c) 1992 Regents of the University of California.
 * All rights reserved.
 *
 * This software was developed by the Computer Systems Engineering group
 * at Lawrence Berkeley Laboratory under DARPA contract BG 91-66 and
 * contributed to Berkeley.
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
 *	California, Lawrence Berkeley Laboratory and its contributors.
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
 *
 *	$Id: net.h,v 1.1 1994/05/08 16:11:28 brezak Exp $
 */

#include "iodesc.h"

#define BA { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }

/* Returns true if n_long's on the same net */
#define	SAMENET(a1, a2, m) ((a1 & m) == (a2 & m))

#define MACPY(s, d) bcopy((char *)s, (char *)d, 6)

#define MAXTMO 20	/* seconds */
#define MINTMO 2	/* seconds */

#define FNAME_SIZE 128
#define	IFNAME_SIZE 16
#define RECV_SIZE 1536	/* XXX delete this */

/* Size of struct ether_header + struct ip + struct udphdr */
#define ETHER_SIZE 14
#define	HEADER_SIZE (ETHER_SIZE + 20 + 8)

extern	u_char bcea[6];
extern	char rootpath[FNAME_SIZE];
extern	char bootfile[FNAME_SIZE];
extern	char hostname[FNAME_SIZE];
extern	char domainname[FNAME_SIZE];
extern	char ifname[IFNAME_SIZE];

extern	n_long myip;
extern	n_long rootip;
extern	n_long swapip;
extern	n_long gateip;
extern	n_long nameip;
extern	n_long mask;

extern	int debug;			/* defined in the machdep sources */

extern struct iodesc sockets[SOPEN_MAX];

/* ARP functions: */

u_char	*arpwhohas __P((struct iodesc *, n_long));

int	sendether __P((struct iodesc *, void *, int, u_char *, int));
int	sendudp __P((struct iodesc *, void *, int));
int	recvudp __P((struct iodesc *, void *, int, time_t));
int	sendrecv __P((struct iodesc *, int (*)(struct iodesc *, void *, int),
	    void *, int, int (*)(struct iodesc *, void *, int), void *, int));
void	*checkudp __P((struct iodesc *, void *, int *));

/* utilties: */

char	*ether_sprintf __P((u_char *));
int	in_cksum __P((void *, int));
char	*intoa __P((n_long));			/* similar to inet_ntoa */

/* Machine-dependent functions: */

time_t	getsecs __P((void));
