/*
 * Copyright (c) 1993 Adam Glass
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
 *	This product includes software developed by Adam Glass.
 * 4. The name of the Author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY Adam Glass ``AS IS'' AND
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
 * $Header: /b/source/CVS/src/sys/arch/sun3/include/pte.h,v 1.6 1994/05/27 14:55:26 gwr Exp $
 */

#ifndef _MACHINE_PTE_H
#define _MACHINE_PTE_H

#define NCONTEXT 8
#define SEGINV 255
#define NPAGSEG 16
#define NSEGMAP 2048

#define PG_VALID   0x80000000
#define PG_WRITE   0x40000000
#define PG_SYSTEM  0x20000000
#define PG_NC      0x10000000
#define PG_TYPE    0x0C000000
#define PG_ACCESS  0x02000000
#define PG_MOD     0x01000000

#define PG_SPECIAL (PG_VALID|PG_WRITE|PG_SYSTEM|PG_NC|PG_ACCESS|PG_MOD)
#define PG_PERM    (PG_VALID|PG_WRITE|PG_SYSTEM|PG_NC)
#define PG_FRAME   0x0007FFFF

#define PG_MOD_SHIFT 24
#define PG_PERM_SHIFT 28

#define PG_MMEM      0
#define PG_OBIO      1
#define PG_VME16D    2
#define PG_VME32D    3
#define PG_TYPE_SHIFT 26

#define PG_INVAL   0x0

#define MAKE_PGTYPE(x) ((x) << PG_TYPE_SHIFT)
#define PG_PGNUM(pte) (pte & PG_FRAME)
#define PG_PA(pte) ((pte & PG_FRAME) <<PGSHIFT)

#define VA_PTE_NUM_SHIFT  13
#define VA_PTE_NUM_MASK (0xF << VA_PTE_NUM_SHIFT)
#define VA_PTE_NUM(va) ((va & VA_PTE_NUM_MASK) >> VA_PTE_NUM_SHIFT)

#define PA_PGNUM(pa) (pa >>PGSHIFT)

#endif /* !_MACHINE_PTE_H*/
