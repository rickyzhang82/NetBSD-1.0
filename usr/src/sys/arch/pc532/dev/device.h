/*-
 * Copyright (c) 1991 The Regents of the University of California.
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
 *
 *	from: @(#)isa_device.h	7.1 (Berkeley) 5/9/91
 *
 *	$Id: device.h,v 1.1.1.1 1993/09/09 23:53:53 phil Exp $
 */

/*
 * Per device structure.
 */
struct pc532_device {
	struct	pc532_driver *pd_driver;
	char   *pd_name;	/* device name */
	int	pd_unit;	/* unit number */
	int	pd_drive;	/* drive number */
	int	pd_flags;	/* flags needed */
	int	pd_alive;	/* device is present */
};

/*
 * Per-driver structure.
 *
 * Each device driver defines entries for a set of routines
 * as well as an array of types which are acceptable to it.
 * These are used at boot time by the configuration program.
 */
struct pc532_driver {
	int	(*probe)();		/* test whether device is present */
	int	(*attach)();		/* setup driver for a device */
	char	*name;			/* device name */
};

extern struct pc532_device pc532_devtab_bio[], pc532_devtab_tty[],
	      		   pc532_devtab_net[];

