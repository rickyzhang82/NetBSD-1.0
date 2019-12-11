/*- Copyright (c) 1988 University of Utah.  Copyright (c) 1982, 1986,
 *1990 The Regents of the University of California.  All rights
 *reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department, and code derived from software contributed to
 * Berkeley by William Jolitz.
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
 * from: Utah $Hdr: mem.c 1.13 89/10/08$
 *	@(#)mem.c	7.2 (Berkeley) 5/9/91
 *
 *	mem.c,v 1.1.1.1 1993/09/09 23:53:47 phil Exp /

/*
 * Memory special file
 */
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/buf.h>
#include <sys/systm.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/fcntl.h>

#include <machine/cpu.h>

#include <vm/vm.h>

extern        char *vmmap;		/* poor name! */

#ifndef NO_RTC
int have_rtc = 1;			/* For access to rtc. */
#else
int have_rtc = 0;			/* For no rtc. */
#endif
#define ROM_ORIGIN	0xFFF00000	/* Mapped origin! */

/* Do the actual reading and writing of the rtc.  We have to read
   and write the entire contents at a time.  rw = 0 => read,
   rw = 1 => write. */

void rw_rtc (unsigned char *buffer, int rw)
{
  static unsigned char magic[8] =
    {0xc5, 0x3a, 0xa3, 0x5c, 0xc5, 0x3a, 0xa3, 0x5c};
  volatile unsigned char * const rom_p = (unsigned char *)ROM_ORIGIN;
  unsigned char *bp;
  unsigned char dummy;         /* To defeat optimization */

  /* Read or write to the real time chip. Address line A0 functions as
   * data input, A2 is used as the /write signal. Accesses to the RTC
   * are always done to one of the addresses (unmapped):
   *
   * 0x10000000  -  write a '0' bit
   * 0x10000001  -  write a '1' bit
   * 0x10000004  -  read a bit
   *
   * Data is output from the RTC using D0. To read or write time
   * information, the chip has to be activated first, to distinguish
   * clock accesses from normal ROM reads. This is done by writing,
   * bit by bit, a magic pattern to the chip. Before that, a dummy read
   * assures that the chip's pattern comparison register pointer is
   * reset. The RTC register file is always read or written wholly,
   * even if we are only interested in a part of it.
   */

  /* Activate the real time chip */
  dummy = rom_p[4]; /* Synchronize the comparison reg. */

  for (bp=magic; bp<magic+8; bp++) {
    int i;
    for (i=0; i<8; i++)
      dummy = rom_p[ (*bp>>i) & 0x01 ];
  }

  if (rw == 0) {			
	/* Read the time from the RTC. Do this even this is
	   a write, since the user might have only given
	   partial data and the RTC must always be written
	   completely.
	*/

	for (bp=buffer; bp<buffer+8; bp++) {
	  int i;
	  for (i=0; i<8; i++) {
	    *bp >>= 1;
	    *bp |= ((rom_p[4] & 0x01) ? 0x80 : 0x00);
	  }
	}
  } else {
	/* Write to the RTC */
	for (bp=buffer; bp<buffer+8; bp++) {
	  int i;
	  for (i=0; i<8; i++)
	    dummy = rom_p[ (*bp>>i) & 0x01 ];
	}
  }
}


/*ARGSUSED*/
mmrw(dev, uio, flags)
	dev_t dev;
	struct uio *uio;
	int flags;
{
	register int o;
	register u_int c, v;
	register struct iovec *iov;
	int error = 0;
	caddr_t zbuf = NULL;

	/* /dev/rtc support. */
	unsigned char buffer[8];


	while (uio->uio_resid > 0 && error == 0) {
		iov = uio->uio_iov;
		if (iov->iov_len == 0) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
			if (uio->uio_iovcnt < 0)
				panic("mmrw");
			continue;
		}
		switch (minor(dev)) {

/* minor device 0 is physical memory */
		case 0:
			v = uio->uio_offset;
			pmap_enter(kernel_pmap, vmmap, v,
				uio->uio_rw == UIO_READ ? VM_PROT_READ : VM_PROT_WRITE,
				TRUE);
			o = (int)uio->uio_offset & PGOFSET;
			c = (u_int)(NBPG - ((int)iov->iov_base & PGOFSET));
			c = min(c, (u_int)(NBPG - o));
			c = min(c, (u_int)iov->iov_len);
			error = uiomove((caddr_t)&vmmap[o], (int)c, uio);
			pmap_remove(kernel_pmap, vmmap, &vmmap[NBPG]);
			continue;

/* minor device 1 is kernel memory */
		case 1:
			c = iov->iov_len;
			if (!kernacc((caddr_t)(long)uio->uio_offset, c,
			    uio->uio_rw == UIO_READ ? B_READ : B_WRITE))
				return(EFAULT);
			error = uiomove((caddr_t)(long)uio->uio_offset, (int)c, uio);
			continue;

/* minor device 2 is EOF/RATHOLE */
		case 2:
			if (uio->uio_rw == UIO_READ)
				return (0);
			c = iov->iov_len;
			break;

#ifdef DEV_RTC
/* minor device 3 is the realtime clock. */
		case 3:
			if (!have_rtc)
				return (ENXIO);

			/* Calc offsets and lengths. */
			v = uio->uio_offset;
			if (v > 8) return(0);  /* EOF */
			c = iov->iov_len;
			if (v+c > 8) c = 8-v;

			rw_rtc ( buffer, 0 );   /* Read the rtc. */

			error = uiomove((caddr_t)&buffer[v], (int)c, uio);

			if (uio->uio_rw == UIO_READ || error)
				return (error);

			rw_rtc ( buffer, 1 );   /* Write the rtc. */

			return (error);
#endif

/* minor device 12 (/dev/zero) is source of nulls on read, rathole on write */
		case 12:
			if (uio->uio_rw == UIO_WRITE) {
				c = iov->iov_len;
				break;
			}
			if (zbuf == NULL) {
				zbuf = (caddr_t)
				    malloc(CLBYTES, M_TEMP, M_WAITOK);
				bzero(zbuf, CLBYTES);
			}
			c = min(iov->iov_len, CLBYTES);
			error = uiomove(zbuf, (int)c, uio);
			continue;

		default:
			return (ENXIO);
		}
		if (error)
			break;
		iov->iov_base += c;
		iov->iov_len -= c;
		uio->uio_offset += c;
		uio->uio_resid -= c;
	}
	if (zbuf)
		free(zbuf, M_TEMP);
	return (error);
}


/* Ram disk stuff.... */
#ifdef RAMD_SIZE

#ifndef RAMD_ADR
#define RAMD_ADR	0x200000	
#endif

u_char ram_disk[RAMD_SIZE];

int rdopen(dev_t dev, int flag)
{
  if (minor(dev) == 0)
    return (0);
  else
    return (ENXIO);
}

int rdclose()
{
  return (0);
}

int rdstrategy(struct buf *bp)
{ int loc, size;
  char *adr;

  if (minor(bp->b_dev) == 0)
    loc = bp->b_blkno*DEV_BSIZE;
  else
    return (EINVAL);
  size = bp->b_bcount;
  adr = (char *) bp->b_un.b_addr;
  if (loc > sizeof(ram_disk)) return (EINVAL);
  if (loc+size > sizeof(ram_disk)) return (EINVAL);
  if (bp->b_flags & B_READ)
	bcopy (&ram_disk[loc], adr, size);
  else
	bcopy (adr, &ram_disk[loc], size);
  biodone(bp);
  return 0;
}

int rdsize(dev_t dev)
{
  if (minor(dev) == 0)
    return (RAMD_SIZE / DEV_BSIZE);
  else
    return (0);
}


void load_ram_disk()
{
  bcopy ((char *)RAMD_ADR, ram_disk, RAMD_SIZE);
}
#endif
