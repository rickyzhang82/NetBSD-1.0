/*
 * Copyright (c) 1994 Michael L. Hitch
 * Copyright (c) 1982, 1990 The Regents of the University of California.
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
 *	@(#)dma.c
 *	$Id: zssc.c,v 1.5 1994/06/16 14:28:58 chopps Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/device.h>
#include <scsi/scsi_all.h>
#include <scsi/scsiconf.h>
#include <amiga/amiga/custom.h>
#include <amiga/amiga/cc.h>
#include <amiga/amiga/device.h>
#include <amiga/dev/siopreg.h>
#include <amiga/dev/siopvar.h>
#include <amiga/dev/ztwobusvar.h>

int zsscprint __P((void *auxp, char *));
void zsscattach __P((struct device *, struct device *, void *));
int zsscmatch __P((struct device *, struct cfdata *, void *));
int siopintr __P((struct siop_softc *));

struct scsi_adapter zssc_scsiswitch = {
	siop_scsicmd,
	siop_minphys,
	0,			/* no lun support */
	0,			/* no lun support */
	siop_adinfo,
	"zssc",
};

struct scsi_device zssc_scsidev = {
	NULL,		/* use default error handler */
	NULL,		/* do not have a start functio */
	NULL,		/* have no async handler */
	NULL,		/* Use default done routine */
	"zssc",
	0,
};


#ifdef DEBUG
#endif

struct cfdriver zssccd = {
	NULL, "zssc", zsscmatch, zsscattach, 
	DV_DULL, sizeof(struct siop_softc), NULL, 0 };

/*
 * if we are an PPI Zeus
 */
int
zsscmatch(pdp, cdp, auxp)
	struct device *pdp;
	struct cfdata *cdp;
	void *auxp;
{
	struct ztwobus_args *zap;

	zap = auxp;
	if (zap->manid == 2026 && zap->prodid == 150)
		return(1);
	return(0);
}

void
zsscattach(pdp, dp, auxp)
	struct device *pdp, *dp;
	void *auxp;
{
	struct siop_softc *sc;
	struct ztwobus_args *zap;
	siop_regmap_p rp;

	printf("\n");

	zap = auxp;
	
	sc = (struct siop_softc *)dp;
	sc->sc_siopp = rp = zap->va + 0x4000;

	/*
	 * DCNTL = 50.01->66MHZ / SCLK/3
	 * CTEST7 = 00
	 */
	sc->sc_clock_freq = 0xc0;

	
	siopinitialize(sc);

	sc->sc_link.adapter_softc = sc;
	sc->sc_link.adapter_targ = 7;
	sc->sc_link.adapter = &zssc_scsiswitch;
	sc->sc_link.device = &zssc_scsidev;
	TAILQ_INIT(&sc->sc_xslist);

#if 1
	custom.intreq = INTF_EXTER;
	custom.intena = INTF_SETCLR | INTF_EXTER;
#endif

	/*
	 * attach all scsi units on us
	 */
	config_found(dp, &sc->sc_link, zsscprint);
}

/*
 * print diag if pnp is NULL else just extra
 */
int
zsscprint(auxp, pnp)
	void *auxp;
	char *pnp;
{
	if (pnp == NULL)
		return(UNCONF);
	return(QUIET);
}


/*
 * Level 6 interrupt processing for the Progressive Peripherals Inc
 * Zeus SCSI.  Because the level 6 interrupt is above splbio, the
 * interrupt status is saved and an sicallback to the level 2 interrupt
 * handler scheduled.  This way, the actual processing of the interrupt
 * can be deferred until splbio is unblocked.
 */

#if 0
int
zssc_dmaintr()
#else
int
siopintr6 ()
#endif
{
	siop_regmap_p rp;
	struct siop_softc *dev;
	int i, istat, found;

	found = 0;
	for (i = 0; i < zssccd.cd_ndevs; i++) {
		dev = zssccd.cd_devs[i];
		if (dev == NULL)
			continue;
		rp = dev->sc_siopp;
		istat = rp->siop_istat;
		if ((istat & (SIOP_ISTAT_SIP | SIOP_ISTAT_DIP)) == 0)
			continue;
		if ((dev->sc_flags & (SIOP_DMA | SIOP_SELECTED)) == SIOP_SELECTED)
			continue;	/* doing non-interrupt I/O */
		found++;
		dev->sc_istat = istat;
		dev->sc_dstat = rp->siop_dstat;
		dev->sc_sstat0 = rp->siop_sstat0;
		custom.intreq = INTF_EXTER;
		add_sicallback (siopintr, dev, NULL);
	}
	return(found);
}
