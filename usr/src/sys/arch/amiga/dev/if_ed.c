/*
 * Copyright (c) 1994 Timo Rossi
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
 *      This product includes software developed by  Timo Rossi
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *	$Id: if_ed.c,v 1.2 1994/07/26 17:51:19 chopps Exp $
 */
/*
 * Driver for the Hydra Systems ethernet card
 * written by Timo Rossi <trossi@jyu.fi>,
 * somewhat based on Amiga if_le.c and i386 if_ed.c
 *
 * 01.07.1994 TR -- First working version
 * 03.07.1994 TR -- Now he_put() should work with odd length mbufs.
 *                  (currently uses an extra buffer/extra memory copy)
 * 13.07.1994 TR -- Some little optimizations...
 *                  Now shouldn't crash the machine if a Hydra board
 *                  is not present.
 * 14.07.1994 TR -- Now shouldn't cause those NFS 'odd length' messages.
 *                  Optimized the transmit routine in case the whole
 *                  packet fits in one mbuf.
 * 14.07.1994 CH -- KNF and make it match the if_ed from i386 as mutch as
 *		    possible, without changing anything.
 */
#include "bpfilter.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/buf.h>
#include <sys/device.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/ioctl.h>
#include <sys/errno.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/netisr.h>

#ifdef INET
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#endif

#ifdef NS
#include <netns/ns.h>
#include <netns/ns_if.h>
#endif

#if NBPFILTER > 0
#include <net/bpf.h>
#include <net/bpfdesc.h>
#endif

#include <machine/cpu.h>
#include <machine/mtpr.h>
#include <amiga/amiga/device.h>
#include <amiga/dev/ztwobusvar.h>
#include <amiga/dev/if_edreg.h>
#include <amiga/amiga/cia.h>		/* XXX? */

/*
 * This currently uses only one transmit buffer
 * always located in the beginning of the card RAM.
 * the rest (or at least 16K that all Hydra cards have)
 * is used for receive buffers
 *
 */
#define ETHER_MIN_LEN 64
#define ETHER_MAX_LEN 1518
#define ETHER_ADDR_LEN 6

/*
 * Ethernet software status per interface
 *
 */
struct ed_softc {
	struct	device sc_dev;
	struct	arpcom sc_arpcom;	/* Common ethernet structures */
	u_char	volatile *sc_base;
	u_char	volatile *sc_nic_base;
	int	sc_next_pkt;
	u_short sc_tx_page_start;
	u_short sc_rx_page_start;
	u_short sc_rx_page_stop;

/* Add other fields as needed... -- TR */

#if NBPFILTER > 0
	caddr_t sc_bpf;
#endif
};

/* prototypes */

int edmatch __P((struct device *, struct cfdata *, void *));
void edattach __P((struct device *, struct device *, void *));
void ed_init __P((struct ed_softc *));
void ed_reset __P((struct ed_softc *));
void ed_stop __P((struct ed_softc *));
int ed_start __P((struct ifnet *));
int ed_ioctl __P((struct ifnet *, int, caddr_t));
int ed_put __P((u_char volatile *, struct mbuf *));

struct cfdriver edcd = {
	NULL, "ed", edmatch, edattach, DV_IFNET, sizeof(struct ed_softc),
};

/*
 * read/write 8390 NIC registers
 *
 */
void inline
write_nic_reg(addr, data)
	u_char volatile *addr;
	int data;
{
	*((u_char *)addr) = data;
	(void)ciaa.pra;
}

u_char inline
read_nic_reg(addr)
	u_char volatile *addr;
{
	register u_char val;

	val = *((u_char *)addr);
	(void) ciaa.pra;
	return (val);
}

int
edmatch(pdp, cfp, auxp)
	struct device *pdp;
	struct cfdata *cfp;
	void *auxp;
{
	struct ztwobus_args *zap;

	zap = auxp;

	if (zap->manid == 2121 && zap->prodid == 1)
		return (1);
	return (0);
}

void
edattach(pdp, dp, auxp)
	struct device *pdp, *dp;
	void *auxp;
{
	struct ztwobus_args *zap;
	struct ed_softc *sc;
	struct ifnet *ifp;
	int i, s;

	zap = auxp;
	sc = (struct ed_softc *)dp;
	ifp = &sc->sc_arpcom.ac_if;

#ifdef ED_DEBUG
	printf("ed_attach(0x%x, 0x%x, 0x%x)\n", pdp, dp, auxp);
#endif
	s = splhigh();
	sc->sc_base = zap->va;
	sc->sc_nic_base = sc->sc_base + HYDRA_NIC_BASE;

	sc->sc_tx_page_start = 0;
	sc->sc_rx_page_start = 6;
	sc->sc_rx_page_stop = 64;

	/*
	 * read the ethernet address from the board
	 */
	for(i = 0; i < ETHER_ADDR_LEN; i++)
		sc->sc_arpcom.ac_enaddr[i] =
		    *((u_char *)(sc->sc_base + HYDRA_ADDRPROM + 2 * i));

	printf(": hardware address %s\n", 
	    ether_sprintf(sc->sc_arpcom.ac_enaddr));
	splx(s);

	/*
	 * set interface to stopped condition (reset)
	 * XXX ed_stop(sc); 
	 */

	ifp->if_unit = sc->sc_dev.dv_unit;
	ifp->if_name = edcd.cd_name;
	ifp->if_output = ether_output;
	ifp->if_start = ed_start;
	ifp->if_ioctl = ed_ioctl;
	/* ifp->if_watchdog  = ed_watchdog */
	ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_NOTRAILERS;
	ifp->if_mtu = ETHERMTU;

#if NBPFILTER > 0
	bpfattach(&sc->sc_bpf, ifp, DLT_EN10MB, sizeof(struct ether_header));
#endif
	if_attach(ifp);
	ether_ifattach(ifp);
}

/*
 * Initialize device
 *
 */
void
ed_init(sc)
	struct ed_softc *sc;
{
	struct ifnet *ifp = &sc->sc_arpcom.ac_if;
	int i, s;
	u_char command;
	u_long mcaf[2];

#ifdef ED_DEBUG
	printf("ed_init(0x%x)\n", sc);
#endif

	/* Address not known. */
	if(ifp->if_addrlist == 0)
		return;

	if((ifp->if_flags & IFF_RUNNING) == 0) {
		s = splimp();
		ifp->if_flags |= IFF_RUNNING;
		ed_reset(sc);
		(void)ed_start(ifp);
		splx(s);
	}
}

/*
 * Reset the interface...
 *
 * this assumes that it is called inside a critical section...
 *
 */
void
ed_reset(sc)
	struct ed_softc *sc;
{
	int i, s;

#ifdef ED_DEBUG
	printf("ed_reset(0x%x)\n", sc);
#endif

	/*
	 * Initialize NIC
	 */
	/* page0, softreset */
	write_nic_reg(sc->sc_nic_base + NIC_CR, CR_PAGE0 | CR_NODMA | CR_STOP);

	/*
	 * word transfer, 68k byteorder, no loopback,
	 * fifo threshold 4 bytes (2 words)
	 */
	write_nic_reg(sc->sc_nic_base + NIC_DCR,
	    DCR_WTS | DCR_BOS | DCR_LS | DCR_FT0);

	/*
	 * clear remote byte count registers
	 */
	write_nic_reg(sc->sc_nic_base + NIC_RBCR0, 0);
	write_nic_reg(sc->sc_nic_base + NIC_RBCR1, 0);

	/*
	 * accept broadcast, and use promiscuous mode if requested
	 */
	if(sc->sc_arpcom.ac_if.if_flags & IFF_PROMISC)
		write_nic_reg(sc->sc_nic_base + NIC_RCR, RCR_AB | RCR_PRO);
	else
		write_nic_reg(sc->sc_nic_base + NIC_RCR, RCR_AB);

	/*
	 * enable loopback mode 1
	 */
	write_nic_reg(sc->sc_nic_base + NIC_TCR, TCR_LB0);

	/*
	 * initialize receive buffer ring
	 */
	write_nic_reg(sc->sc_nic_base + NIC_PSTART, sc->sc_rx_page_start);
	write_nic_reg(sc->sc_nic_base + NIC_PSTOP, sc->sc_rx_page_stop);
	write_nic_reg(sc->sc_nic_base + NIC_BNDRY, sc->sc_rx_page_start);

	/*
	 * clear interrupts
	 */
	write_nic_reg(sc->sc_nic_base + NIC_ISR, 0xff);

	/*
	 * enable interrupts (doesn't enable counter overflow interrupt)
	 */
	write_nic_reg(sc->sc_nic_base + NIC_IMR,
	    ISR_PRX | ISR_PTX | ISR_RXE | ISR_TXE | ISR_OVW);

	/*
	 * go to page 1
	 */
	write_nic_reg(sc->sc_nic_base + NIC_CR, CR_PAGE1 | CR_NODMA | CR_STOP);

	/*
	 * set physical ethernet address
	 */
	for(i = 0; i < ETHER_ADDR_LEN; i++)
		write_nic_reg(sc->sc_nic_base + NIC_PAR0 + 2 * i,
		    sc->sc_arpcom.ac_enaddr[i]);

	sc->sc_next_pkt = sc->sc_rx_page_start + 1;
	write_nic_reg(sc->sc_nic_base + NIC_CURR, sc->sc_next_pkt);

	/*
	 * go to page 0, start NIC
	 */
	write_nic_reg(sc->sc_nic_base + NIC_CR, CR_PAGE0 | CR_NODMA | CR_START);

	/*
	 * clear interrupts again
	 */
	write_nic_reg(sc->sc_nic_base + NIC_ISR, 0xff);

	/*
	 * take interface out of loopback
	 */
	write_nic_reg(sc->sc_nic_base + NIC_TCR, 0);

	sc->sc_arpcom.ac_if.if_flags |= IFF_RUNNING;
	sc->sc_arpcom.ac_if.if_flags &= ~IFF_OACTIVE;

	ed_start(&sc->sc_arpcom.ac_if);
}

/*
 * Take interface offline
 */
void
ed_stop(sc)
	struct ed_softc *sc;
{
	int n = 5000;

	/* Stop the interface */
	write_nic_reg(sc->sc_nic_base + NIC_CR, CR_PAGE0 | CR_NODMA | CR_STOP);

	/* Wait until interface has entered stopped state (or timeout) */
	while(((read_nic_reg(sc->sc_nic_base +NIC_ISR) & ISR_RST) == 0) && --n);
}

/*
 * Start output on interface. Get another datagram to send
 * off the interface queue, and copy it to the
 * interface becore starting the output
 *
 * this assumes that it is called inside a critical section...
 *
 */
int
ed_start(ifp)
	struct ifnet *ifp;
{
	struct ed_softc *sc = edcd.cd_devs[ifp->if_unit];
	struct mbuf *m;
	int len, s;

#ifdef ED_DEBUG
	printf("ed_start(0x%x)\n", ifp);
#endif

	if((sc->sc_arpcom.ac_if.if_flags & IFF_RUNNING) == 0)
		return 0;

	IF_DEQUEUE(&sc->sc_arpcom.ac_if.if_snd, m);
	if(m == 0)
		return 0;

#if NBPFILTER > 0
	/*
	 * If bpf is listening on this interface, let it
	 * see the packet before we commit it to the wire
	 *
	 * (can't give the copy in Hydra card RAM to bpf, because
	 * that RAM must always be accessed as words or longwords)
	 *
	 */
	if(sc->sc_bpf)
		bpf_mtap(sc->sc_bpf, m);
#endif

	len = ed_put(sc->sc_base + (sc->sc_tx_page_start << 8), m);

	/*
	 * Really transmit a packet
	 */

	/* make sure we are on the correct page */
	write_nic_reg(sc->sc_nic_base + NIC_CR, CR_PAGE0 | CR_START | CR_NODMA);

	/* set transmit page start */
	write_nic_reg(sc->sc_nic_base + NIC_TPSR, sc->sc_tx_page_start);

	/* set packet length */
	write_nic_reg(sc->sc_nic_base + NIC_TBCR0, len & 0xff);
	write_nic_reg(sc->sc_nic_base + NIC_TBCR1, len >> 8);

	/* actually transmit the packet */
	write_nic_reg(sc->sc_nic_base + NIC_CR,
	    CR_PAGE0 | CR_START | CR_NODMA | CR_TXP);

	sc->sc_arpcom.ac_if.if_flags |= IFF_OACTIVE;

	/* maybe add a transmit timeout timer... ?? */
	return 0;
}

/*
 * Memory copy, copies word at time
 */
void inline
word_copy(u_short *a, u_short *b, int len)
{
	len /= 2;
	while(len--)
		*b++ = *a++;
}


/*
 * Copy packet from mbuf to the board memory
 *
 * Currently uses an extra buffer/extra memory copy,
 * unless the whole packet fits in one mbuf.
 *
 */
int
ed_put(addr, m)
	u_char volatile *addr;
	struct mbuf *m;
{
	struct mbuf *mp;
	int len, tlen;
	static u_short packet_buf[1536/2];
	u_char *p;

	/* the whole packet in one mbuf? */
	if(m->m_next == NULL) {
		tlen = m->m_len;
		word_copy(mtod(m, u_short *), (u_short *)addr, tlen+1);
	} else {
		for(p = (u_char *)packet_buf, tlen = 0, mp = m;
		    mp; mp = mp->m_next) {
			if((len = mp->m_len) == 0)
				continue;
			tlen += len;
			bcopy(mtod(mp, u_char *), p, len);
			p += len;
		}
		if((len = tlen) & 1)
			len++;
		word_copy(packet_buf, (u_short *)addr, len);
	}
	m_freem(m);

	if(tlen < (ETHER_MIN_LEN-4)) {
		tlen = ETHER_MIN_LEN - 4;
		/*
		 * should probably clear the rest of the packet 
		 * in the transmit buffer...
		 */
	}
	return (tlen);
}

/*
 * Copy packet from board RAM
 *
 * Trailers not (yet) supported
 *
 */
void
ed_get_packet(sc, nic_ram_ptr, len)
	struct ed_softc *sc;
	u_short volatile *nic_ram_ptr;
	int len;
{
	struct ether_header *eh;
	struct mbuf *m, *dst, *head = 0;
	int len1, amount;
	u_short *rec_buf_end =
	    (u_short *)(sc->sc_base+(sc->sc_rx_page_stop<<8));

	/* round the length to a word boundary */
	len = (len + 1) & ~1;

	/* Allocate header mbuf */
	MGETHDR(m, M_DONTWAIT, MT_DATA);
	if(m == 0)
		goto bad;
  
	m->m_pkthdr.rcvif = &sc->sc_arpcom.ac_if;
	m->m_pkthdr.len = len;
	m->m_len = 0;
	head = m;

	/* This should solve the NFS odd length packet problem... */
	head->m_data += (((sizeof(struct ether_header) + 3) & ~3) -
	    sizeof(struct ether_header));

	eh = mtod(head, struct ether_header *);

	word_copy((u_short *)nic_ram_ptr, mtod(head, u_short *),
	    sizeof(struct ether_header));

	nic_ram_ptr += sizeof(struct ether_header)/2;
	head->m_len += sizeof(struct ether_header);
	len -= sizeof(struct ether_header);

	/* NOTE: nic_ram_ptr & rec_buf_end are u_short pointers */

	while(len > 0) {
		if(nic_ram_ptr >= rec_buf_end) /* buffer pointer wrap */
			nic_ram_ptr =
			    (u_short *)(sc->sc_base +
			    (sc->sc_rx_page_start << 8));

		len1 = (rec_buf_end - nic_ram_ptr) * 2;
		if(len1 > len)
			len1 = len;

		amount = M_TRAILINGSPACE(m);
		if(amount == 0) {
			/* allocate another mbuf */
			dst = m;
			MGET(m, M_DONTWAIT, MT_DATA);
			if(m == 0)
				goto bad;

			if(len1 >= MINCLSIZE)
				MCLGET(m, M_DONTWAIT);

			m->m_len = 0;
			dst->m_next = m;

			amount = M_TRAILINGSPACE(m);
		}

		if(amount < len1)
			len1 = amount;

		if(len1 & 1)
			printf("ed_get_packet() ERROR: odd len for wcopy()\n");

#ifdef ED_DEBUG
		printf("copying %d bytes (%d left)\n", len1, len - len1);
#endif

		word_copy((u_short *)nic_ram_ptr,
		    (u_short *)(mtod(m, caddr_t) + m->m_len), len1);

		m->m_len += len1;
		nic_ram_ptr += len1 / 2;
		len -= len1;
	}

#if NBPFILTER > 0
	if(sc->sc_bpf) {
		bpf_mtap(sc->sc_bpf, head);

		/*
		 * The interface cannot be in promiscuous mode if there are
		 * no BPF listeners. And in prom. mode we have to check
		 * if the packet is really ours...
		 */
		if((sc->sc_arpcom.ac_if.if_flags & IFF_PROMISC) &&
		    (eh->ether_dhost[0] & 1) == 0 && /* not bcast or mcast */
		    bcmp(eh->ether_dhost, sc->sc_arpcom.ac_enaddr,
			ETHER_ADDR_LEN) != 0) {
			m_freem(head);
			return;
		}
	}
#endif

	m_adj(head, sizeof(struct ether_header));
	ether_input(&sc->sc_arpcom.ac_if, eh, head);
	return;

bad:
	if(head)
		m_freem(head);
	return;
}


/*
 * Ethernet interface receiver interrupt.
 */
void
ed_rint(sc)
	struct ed_softc *sc;
{
	u_short volatile *nic_ram_ptr;
	int boundary, hdr_next_pkt, len;

	/* select page1 to access the NIC_CURR register */
	write_nic_reg(sc->sc_nic_base + NIC_CR, CR_PAGE1 | CR_START | CR_NODMA);

	while(sc->sc_next_pkt != read_nic_reg(sc->sc_nic_base + NIC_CURR)) {
		nic_ram_ptr = (u_short *)(sc->sc_base + (sc->sc_next_pkt << 8));
		hdr_next_pkt = nic_ram_ptr[0];
		hdr_next_pkt >>= 8;

		len = nic_ram_ptr[1];
		len = (len >> 8) | ((len & 0xff) << 8); /* byte order fix */

#ifdef ED_DEBUG
		printf("hdr_next_pkt = 0x%x, packet length = %d\n",
		    hdr_next_pkt, len);
#endif

		if(len >= ETHER_MIN_LEN && len <= ETHER_MAX_LEN) {
			/*
			 * note that nic_ram_ptr is u_short *, so
			 * adding 2 actually adds 4 bytes.
			 * CRC is not included in packet length
			 */
			ed_get_packet(sc, nic_ram_ptr+2, len-4);
			++sc->sc_arpcom.ac_if.if_ipackets;
		} else {
			/*
			 * Hmm... something is wrong... but this might also
			 * happen when an oversized packet arrives...
			 * but just reset the NIC
			 */
			log(LOG_ERR,
			    "%s: NIC memory corrupt - invalid packet len %d\n",
			    sc->sc_dev.dv_xname, len);
			++sc->sc_arpcom.ac_if.if_ierrors;
			ed_reset(sc);
			return;
		}

		/* Update next packet pointer. */
		sc->sc_next_pkt = hdr_next_pkt;

		/*
		 * Update NIC boundary pointer - being careful to keep it one
		 * buffer behind (as recommended by NS databook).
		 */
		boundary = sc->sc_next_pkt - 1;
		if(boundary < sc->sc_rx_page_start)
			boundary = sc->sc_rx_page_stop-1;

#ifdef ED_DEBUG
		printf("new boundary value = %d\n", boundary);
#endif

		/* set NIC to page 0 to update the NIC_BNDRY register */
		write_nic_reg(sc->sc_nic_base + NIC_CR,
		    CR_PAGE0 | CR_START | CR_NODMA);
		write_nic_reg(sc->sc_nic_base+NIC_BNDRY, boundary);

		/* select page1 to access the NIC_CURR register */
		write_nic_reg(sc->sc_nic_base + NIC_CR,
		    CR_PAGE1 | CR_START | CR_NODMA);
	}
}


/*
 * Our interrupt routine
 */
int
edintr(unit)
	int unit;
{
	struct ed_softc *sc = edcd.cd_devs[unit];
	u_char isr;
	u_char xmit_flag;

	/*
	 * If the driver has not been initialized, just return immediately
	 * This also happens if there is no Hydra board present
	 */
	if (edcd.cd_devs == NULL || (sc = edcd.cd_devs[unit]) == NULL)
		return (0);

	xmit_flag = 0;

	/* Set NIC to page 0 registers. */
	write_nic_reg(sc->sc_nic_base + NIC_CR, CR_PAGE0 | CR_START | CR_NODMA);

	/* get interrupt status */
	isr = read_nic_reg(sc->sc_nic_base + NIC_ISR) & 0x7f;
	if(!isr)
		return 0;

#ifdef ED_DEBUG
	printf("ed_intr(0x%x), isr 0x%x\n", sc, isr);
#endif

	/* Loop until there are no more new interrupts. */
	for (;;) {
		/*
		 * Reset all the bits that we are 'acknowledging' by writing a
		 * '1' to each bit position that was set.
		 * (Writing a '1' *clears* the bit.)
		 */
		write_nic_reg(sc->sc_nic_base + NIC_ISR, isr);

		/*
		 * Handle transmitter interrupts.  Handle these first because
		 * the receiver will reset the board under some conditions.
		 */
		if(isr & (ISR_PTX | ISR_TXE)) {
			u_char collisions;

			collisions = read_nic_reg(sc->sc_nic_base + NIC_NCR)
			    & 0x0f;

			/*
			 * Check for transmit error.  If a TX completed with an
			 * error, we end up throwing the packet away.  Really
			 * the only error that is possible is excessive
			 * collisions, and in this case it is best to allow the
			 * automatic mechanisms of TCP to backoff the flow.  Of
			 * course, with UDP we're screwed, but this is expected
			 * when a network is heavily loaded.
			 */
			(void)read_nic_reg(sc->sc_nic_base+NIC_TSR);

			if(isr & ISR_TXE) {
				/*
				 * Excessive collisions (16).
				 */
				if((read_nic_reg(sc->sc_nic_base+NIC_TSR)
				    & TSR_ABT) && collisions == 0)
					collisions = 16;
				/* Update output errors counter. */
				sc->sc_arpcom.ac_if.if_oerrors++;
			} else {
				/*
				 * Update total number of successfully
				 * transmitted packets.
				 */
				sc->sc_arpcom.ac_if.if_opackets++;
			}

#ifdef ED_DEBUG
			printf("transmit complete, collisions = %d\n",
			    collisions);
#endif
			sc->sc_arpcom.ac_if.if_flags &= ~IFF_OACTIVE;
			sc->sc_arpcom.ac_if.if_collisions += collisions;
			xmit_flag = 1;
		}


		/* Handle receiver interrupts. */
		if(isr & (ISR_PRX | ISR_RXE | ISR_OVW)) {
			/*
			 * Overwrite warning.  In order to make sure that a
			 * lockup of the local DMA hasn't occurred, we reset
			 * and re-init the NIC.  The NSC manual suggests only a
			 * partial reset/re-init is necessary - but some chips
			 * seem to want more.  The DMA lockup has been seen
			 * only with early rev chips - Methinks this bug was
			 * fixed in later revs.  -DG
			 *
			 * not currently doing DMA methinks - CH.
			 */
			if(isr & ISR_OVW) {
				++sc->sc_arpcom.ac_if.if_ierrors;
#ifdef DIAGNOSTIC
				log(LOG_WARNING,
				    "%s: warning - receiver ring buf overrun\n",
				    sc->sc_dev.dv_xname);
#endif
				/* Stop/reset/re-init NIC. */
				ed_reset(sc);
			} else {
				/*
				 * Receiver Error.  One or more of: CRC error,
				 * frame alignment error FIFO overrun, or
				 * missed packet.
				 */
				if(isr & ISR_RXE) {
					++sc->sc_arpcom.ac_if.if_ierrors;
#ifdef ED_DEBUG
					printf("%s: receive error %x\n",
					    sc->sc_dev.dv_xname,
					    read_nic_reg(sc->sc_nic_base
					    + NIC_RSR));
#endif
				} else /* packet received ok */
				    ed_rint(sc);
			}
		}

		if(xmit_flag)
			ed_start(&sc->sc_arpcom.ac_if);

		write_nic_reg(sc->sc_nic_base + NIC_CR,
		    CR_PAGE0 | CR_START | CR_NODMA);

		/*
		 * If the Network Talley Counters overflow, read them to reset
		 * them.  It appears that old 8390's won't clear the ISR flag
		 * otherwise - resulting in an infinite loop.
		 */
		if(isr & ISR_CNT) {
			(void)read_nic_reg(sc->sc_nic_base+NIC_CNTR0);
			(void)read_nic_reg(sc->sc_nic_base+NIC_CNTR1);
			(void)read_nic_reg(sc->sc_nic_base+NIC_CNTR2);
		}

		isr = read_nic_reg(sc->sc_nic_base+NIC_ISR) & 0x7f;
		if (!isr)
			return 1;
	}
}

/*
 * Process an ioctl request.  This code needs some work - it looks pretty ugly.
 */
int
ed_ioctl(ifp, command, data)
	register struct ifnet *ifp;
	int command;
	caddr_t data;
{
	struct ed_softc *sc = edcd.cd_devs[ifp->if_unit];
	register struct ifaddr *ifa = (struct ifaddr *)data;
	int s, error = 0;

	s = splimp();

#ifdef ED_DEBUG
	printf("he_ioctl() called, cmd = 0x%x\n", cmd);
#endif

	switch(command) {
	case SIOCSIFADDR:
		ifp->if_flags |= IFF_UP;
		switch(ifa->ifa_addr->sa_family) {
#ifdef INET
		case AF_INET:
			ed_init(sc);	 /* before arpwhohas */
			((struct arpcom *)ifp)->ac_ipaddr =
			    IA_SIN(ifa)->sin_addr;
			arpwhohas((struct arpcom *)ifp, 
			    &IA_SIN(ifa)->sin_addr);
			break;
#endif
#ifdef NS
		/* XXX - This code is probably wrong. */
		case AF_NS:
		    {
			struct ns_addr *ina = &(IA_SNS(ifa)->sns_addr);

			if(ns_nullhost(*ina))
				ina->x_host =
				    *(union ns_host *)(sc->sc_arpcom.sc_enaddr);
			else {
				bcopy(ina->x_host.c_host,
				    sc->sc_arpcom.ac_enaddr, ETHER_ADDR_LEN);
			}
			ed_init(sc);
			break;
		    }
#endif
		default:
			ed_init(sc);
			break;
		}

	case SIOCSIFFLAGS:
		if((ifp->if_flags & IFF_UP) == 0 &&
		    (ifp->if_flags & IFF_RUNNING) != 0) {
			/*
			 * If interface is marked down and it is running, then
			 * stop it.
			 */
			ed_stop(sc);
			ifp->if_flags &= IFF_RUNNING;
		} else if((ifp->if_flags & IFF_UP) != 0 &&
		    (ifp->if_flags & IFF_RUNNING) == 0) {
			/*
			 * If interface is marked up and it is stopped, then
			 * start it.
			 */
			ed_init(sc);
		} else {
			/*
			 * Reset the interface to pick up changes in any other
			 * flags that affect hardware registers.
			 */
			ed_stop(sc);
			ed_init(sc);
		}
		break;

		/* Multicast not (yet) supported */
	default:
		error = EINVAL;
	}
	(void) splx(s);
	return error;
}
