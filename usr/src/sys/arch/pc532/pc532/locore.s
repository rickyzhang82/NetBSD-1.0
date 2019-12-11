/*
 * Copyright (c) 1993 Philip A. Nelson.
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
 *	This product includes software developed by Philip A. Nelson.
 * 4. The name of Philip A. Nelson may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PHILIP NELSON ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL PHILIP NELSON BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *	locore.s
 *
 *	locore.s,v 1.2 1993/09/13 07:26:47 phil Exp
 */

/*
 * locore.s  - -  assembler routines needed for BSD stuff.  (ns32532/pc532)
 *
 * Phil Nelson, Dec 6, 1992
 *
 */

/* This is locore.s! */
#define LOCORE

/* Get the defines... */
#include <machine/asm.h>
#include <machine/icu.h>
#include "assym.h"
#include "aic.h"
#include "dp.h"
#include "ncr.h"

/* Includes and defines for the net software interrupts. */
#include "net/netisr.h"
/* #include "inet.h" ???? needed? */

/* Net support. */
#define DONET(s,c)  \
	.globl c ;\
	movd	1<<s, r0 ;\
	andd	_netisr(pc), r0 ;\
	cmpqd	0, r0 ;\
	beq	1f ;\
	bsr	c ;\
1:

/* define some labels */
#define PSR_U 0x100
#define PSR_S 0x200
#define PSR_P 0x400
#define PSR_I 0x800

#define CFG_IVEC 0x1
#define CFG_FPU	 0x2
#define CFG_MEM  0x4
#define CFG_DE	 0x100
#define CFG_DATA 0x200
#define CFG_DLCK 0x400
#define CFG_INS  0x800
#define CFG_ILCK 0x1000

/* Initial Kernel stack page and the Idle processes' stack. */
#define KERN_INT_SP    0xFFC00FFC	

/* Global Data */

.data
.globl _cold, __save_sp, __save_fp, __old_intbase
_cold:		.long 0
__save_sp: 	.long 0
__save_fp: 	.long 0
__old_intbase:	.long 0
__have_fpu:	.long 0

/* spl... support.... */
.globl	_PL_bio, _PL_tty, _PL_net, _PL_zero
Cur_pl:		.long	0x0fffffff	/* All inhibited but not zero! */
_PL_bio:	.long   0		/* Initial values for these. */
_PL_tty:	.long   0
_PL_net:	.long   0
_PL_zero:	.long	0

.text
.globl start
start:
	br here_we_go

	.align 4
.globl  __boot_flags	/* First cut at flags from a boot program */
__boot_flags:
	.long 0		/* 0 => nothing sent in by boot loader. */
	.long 0		/* Other information? */

	.align 4	/* So the trap table is double aligned. */
int_base_tab:		/* Here is the fixed jump table for traps! */
	.long __trap_nvi
	.long __trap_nmi
	.long __trap_abt
	.long __trap_slave
	.long __trap_ill
	.long __trap_svc
	.long __trap_dvz
	.long __trap_flg
	.long __trap_bpt
	.long __trap_trc
	.long __trap_und
	.long __trap_rbe
	.long __trap_nbe
	.long __trap_ovf
	.long __trap_dbg
	.long __trap_reserved

.globl _int_table
_int_table:		/* Here is the fixed jump table for interrupts! */
	.long __int_bad		/* 0 */
	.long __int_bad		/* 1 */
	.long __int_clk		/* 2 - highest priority */
	.long __int_bad		/* 3 */
	.long __int_scsi1	/* 4 - NCR DP8490 */
	.long __int_scsi0	/* 5 - Adaptec 6250 */
	.long __int_bad		/* 6 */
	.long __int_uart3	/* 7 - uart 3*/
	.long __int_bad		/* 8 */
	.long __int_uart2	/* 9  - uart 2*/
	.long __int_bad		/* 10 */
	.long __int_uart1	/* 11 - uart 1*/
	.long __int_bad		/* 12 */
	.long __int_uart0	/* 13 - uart 0*/
	.long __int_bad		/* 14 */
	.long __int_bad		/* 15 */

here_we_go:	/* This is the actual start of the locore code! */

	bicpsrw	PSR_I			/* make sure interrupts are off. */
	bicpsrw	PSR_S			/* make sure we are using sp0. */
	lprd    sb, 0			/* gcc expects this. */
	sprd	sp, __save_sp(pc)  	/* save monitor's sp. */
	sprd	fp, __save_fp(pc)  	/* save monitor's fp. */
	sprd	intbase, __old_intbase(pc)  /* save monitor's intbase. */

.globl	_bootdev
.globl	_boothowto
	/* Save the registers loaded by the boot program ... if the kernel
		was loaded by the boot program. */
	cmpd	0xc1e86394, r3
	bne	zero_bss
	movd	r7, _boothowto(pc)
	movd	r6, _bootdev(pc)

zero_bss:	
	/* Zero the bss segment. */
	addr	_end(pc),r0	# setup to zero the bss segment.
	addr	_edata(pc),r1
	subd	r1,r0		# compute _end - _edata
	movd	r0,tos		# push length
	addr	_edata(pc),tos	# push address
	bsr	_bzero		# zero the bss segment

#ifdef RAMD_SIZE
	bsr	_load_ram_disk	# Temporary ???
#endif

	bsr __low_level_init	/* Do the low level setup. */

	lprd	sp, KERN_INT_SP # use the idle/interrupt stack.
	lprd	fp, KERN_INT_SP # use the idle/interrupt stack.

	/* Load cfg register is bF7 (IC,DC,DE,M,F,I) or bF5 */
	sprd	cfg, r0
	tbitb	1, r0		/* Test the F bit! */
	bfc	cfg_no_fpu
	movqd	1, __have_fpu(pc)
	lprd	cfg, 0xbf7
	br	jmphi
	
cfg_no_fpu:
	lprd	cfg, 0xbf5

/* Now jump to high addresses after starting mapping! */

jmphi:	
	addr here(pc), r0
	ord  KERNBASE, r0
	jump 0(r0)

here:
	lprd	intbase, int_base_tab  /* set up the intbase.  */

	/* stack and frame pointer are pointing at high memory. */

	bsr 	_init532	/* Set thing up to call main()! */

	/* Get the proc0 kernel stack and pcb set up. */
	movd	KERN_STK_START, r1 	/* Standard sp start! */
	lprd	sp, r1		/* Load it! */
	lprd	fp, USRSTACK	/* fp for the user. */
	lprd	usp, USRSTACK	/* starting stack for the user. */

	/* Build the "trap" frame to return to address 0 in user space! */
	movw	PSR_I|PSR_S|PSR_U, tos	/* psr - user/user stack/interrupts */
	movw	0, tos			/* mod - 0! */
	movd	0, tos			/* pc  - 0 after module table */
	enter	[],8		/* Extra space is for USP */
	movqd	0, tos		/* Zero the registers in the pcb. */
	movqd	0, tos
	movqd	0, tos
	movqd	0, tos
	movqd	0, tos
	movqd	0, tos
	movqd	0, tos
	movqd	0, tos
	movqd	0, REGS_SB(sp)

	/* Now things should be ready to start _main! */

	addr	0(sp), tos
	bsr 	_main		/* Start the kernel! */
	movd	tos, r0		/* Pop addr */

	/* We should only get here in proc 1. */
	movd	_curproc(pc), r1
	cmpqd	0, r1
	beq	main_panic
	movd	P_PID(r1),r0
	cmpqd	1, r0
	bne	main_panic
	lprd	usp, REGS_USP(sp)
	lprd	sb, REGS_SB(sp)

	exit	[r0,r1,r2,r3,r4,r5,r6,r7]
	rett	0	

main_panic:
	addr	main_panic_str(pc), tos
	bsr	_panic

main_panic_str:
	.asciz	"After main -- no curproc or not proc 1."

/* Signal support */
.align 2
.globl _sigcode
.globl _esigcode
_sigcode:
	jsr	0(12(sp))
	movd	103, r0
	svc
.align 2
_esigcode:

/* To get the ptb0 register set correctly. */

ENTRY(_load_ptb0)
	movd	S_ARG0, r0
	andd	~KERNBASE, r0
	lmr 	ptb0, r0
	ret 0

ENTRY(_load_ptb1)
	movd	S_ARG0, r0
	andd	~KERNBASE, r0
	lmr 	ptb1, r0
	ret 0

ENTRY (_get_ptb0)
	smr ptb0, r0
	ret 0

ENTRY (tlbflush)
	smr ptb0, r0
	lmr ptb0, r0
	ret 0

ENTRY (_get_sp_adr)		/* for use in testing.... */
	addr 4(sp), r0
	ret 0

ENTRY (_get_ret_adr)
	movd 0(sp), r0
	ret 0

ENTRY (_get_fp_ret)
	movd 4(fp), r0
	ret 0

ENTRY (_get_2fp_ret)
	movd 4(0(fp)), r0
	ret 0

ENTRY (_get_fp)
	addr 0(fp), r0
	ret 0

/* reboot the machine :)  if possible */

ENTRY(low_level_reboot)

	ints_off			/* Stop things! */
	addr	xxxlow(pc), r0		/* jump to low memory */
	andd	~KERNBASE, r0
	movd	r0, tos
	ret	0
xxxlow:
	lmr	mcr, 0 			/* Turn off mapping. */
	lprd	sp, __save_sp(pc)  	/* get monitor's sp. */
	jump	0x10000000		/* Jump to the ROM! */


/* To get back to the rom monitor .... */
ENTRY(bpt_to_monitor)

/* Switch to monitor's stack. */
	ints_off
	bicpsrw	PSR_S			/* make sure we are using sp0. */
	sprd	psr, tos		/* Push the current psl. */
	save	[r1,r2,r3,r4]
	sprd	sp, r1  		/* save kernel's sp */
	sprd	fp, r2  		/* save kernel's fp */
	sprd	intbase, r3		/* Save current intbase. */
	smr	ptb0, r4		/* Save current ptd! */	

/* Change to low addresses */
	lmr	ptb0, _IdlePTD(pc)	/* Load the idle ptd */
	addr	low(pc), r0
	andd	~KERNBASE, r0
	movd	r0, tos
	ret	0

low:
/* Turn off mapping. */
	smr	mcr, r0
	lmr	mcr, 0
	lprd	sp, __save_sp(pc)	/* restore monitors sp */
	lprd	fp, __save_fp(pc)	/* restore monitors fp */
	lprd	intbase, __old_intbase(pc)	/* restore monitors intbase */
	bpt

/* Reload kernel stack AND return. */
	lprd	intbase, r3		/* restore kernel's intbase */
	lprd	fp, r2			/* restore kernel's fp */
	lprd	sp, r1			/* restore kernel's sp */
	lmr	mcr, r0
	addr	highagain(pc), r0
	ord  	KERNBASE, r0
	jump 	0(r0)
highagain:
	lmr	ptb0, r4		/* Get the last ptd! */
	restore	[r1,r2,r3,r4]
	lprd	psr, tos		/* restore psl */
	ints_on
	ret 0


/*===========================================================================*
 *				ram_size				     *
 *===========================================================================*

 char *
 ram_size (start)
 char *start;

 Determines RAM size.

 First attempt: write-and-read-back (WRB) each page from start
 until WRB fails or get a parity error.  This didn't work because
 address decoding wraps around.

 New algorithm:

	ret = round-up-page (start);
  loop:
	if (!WRB or parity or wrap) return ret;
	ret += pagesz;  (* check end of RAM at powers of two *)
	goto loop;

 Several things make this tricky.  First, the value read from
 an address will be the same value written to the address if
 the cache is on -- regardless of whether RAM is located at
 the address.  Hence the cache must be disabled.  Second,
 reading an unpopulated RAM address is likely to produce a
 parity error.  Third, a value written to an unpopulated address
 can be held by capacitance on the bus and can be correctly
 read back if there is no intervening bus cycle.  Hence,
 read and write two patterns.

*/

cfg_dc		= 0x200
pagesz		= 0x1000
pattern0	= 0xa5a5a5a5
pattern1	= 0x5a5a5a5a
nmi_vec		= 0x44
parity_clr	= 0x28000050

/*
 r0	current page, return value
 r1	old config register
 r2	temp config register
 r3	pattern0	
 r4	pattern1
 r5	old nmi vector
 r6	save word at @0
 r7	save word at @4
*/
.globl _ram_size
_ram_size:
	enter	[r1,r2,r3,r4,r5,r6,r7],0
	# initialize things
	movd	@0,r6		#save 8 bytes of first page
	movd	@4,r7
	movd	0,@0		#zero 8 bytes of first page
	movd	0,@4
	sprw	cfg,r1		#turn off data cache
	movw	r1,r2		#r1 = old config
	andw	~cfg_dc,r2	# was: com cfg_dc,r2
	lprw	cfg,r2
	movd	@nmi_vec,r5	#save old NMI vector
	addr	tmp_nmi(pc),@nmi_vec	#tmp NMI vector
	movd	8(fp),r0	#r0 = start
	addr	pagesz-1(r0),r0	#round up to page
	andd	~(pagesz-1),r0	# was: com (pagesz-1),r0
	movd	pattern0,r3
	movd	pattern1,r4
rz_loop:
	movd	r3,0(r0)	#write 8 bytes
	movd	r4,4(r0)
	lprw	cfg,r2		#flush write buffer
	cmpd	r3,0(r0)	#read back and compare
	bne	rz_exit
	cmpd	r4,4(r0)
	bne	rz_exit
	cmpqd	0,@0		#check for address wrap
	bne	rz_exit
	cmpqd	0,@4		#check for address wrap
	bne	rz_exit
	addr	pagesz(r0),r0	#next page
	br	rz_loop
rz_exit:
	movd	r6,@0		#restore 8 bytes of first page
	movd	r7,@4
	lprd	cfg,r1		#turn data cache back on
	movd	r5,@nmi_vec	#restore NMI vector
	movd	parity_clr,r2
	movb	0(r2),r2	#clear parity status
	exit	[r1,r2,r3,r4,r5,r6,r7]
	ret	0

tmp_nmi:				#come here if parity error
	addr	rz_exit(pc),0(sp)	#modify return addr to exit
	rett	0

/* Low level kernel support routines. */

/* External symbols that are needed. */
/* .globl EX(cnt) */
.globl EX(curproc)
.globl EX(curpcb)
.globl EX(qs)
.globl EX(whichqs)
.globl EX(want_resched)
.globl EX(want_softclock)
.globl EX(want_softnet)
.globl EX(spl0)


/*
   User/Kernel copy routines ... {fu,su}{word,byte} and copyin/coyinstr

   These are "Fetch User" or "Save user" word or byte.  They return -1 if
   a page fault occurs on access. 
*/

ENTRY(fuword)
ENTRY(fuiword)
	enter	[r2],0
	movd	_curpcb(pc), r2
	addr	fusufault(pc), PCB_ONFAULT(r2)
	movd	0(B_ARG0), r0
	br	fusu_ret

ENTRY(fubyte)
ENTRY(fuibyte)
	enter	[r2],0
	movd	_curpcb(pc), r2
	addr	fusufault(pc), PCB_ONFAULT(r2)
	movzbd	0(B_ARG0), r0
	br	fusu_ret

ENTRY(suword)
ENTRY(suiword)
	enter	[r2],0
	movqd	4, tos
	movd	B_ARG0, tos
	bsr	_check_user_write
	adjspb	-8
	cmpqd	0, r0
	bne	fusufault
	movd	_curpcb(pc), r2
	addr	fusufault(pc), PCB_ONFAULT(r2)
	movqd	0, r0
	movd	B_ARG1,0(B_ARG0)
	br	fusu_ret

ENTRY(subyte)
ENTRY(suibyte)
	enter	[r2],0
	movqd	1, tos
	movd	B_ARG0, tos
	bsr	_check_user_write
	adjspb	-8
	cmpqd	0, r0
	bne	fusufault
	movd	_curpcb(pc), r2
	addr	fusufault(pc), PCB_ONFAULT(r2)
	movqd	0, r0
	movb	B_ARG1, 0(B_ARG0)
	br	fusu_ret

fusufault:
	movqd	-1, r0
fusu_ret:
	movqd	0, PCB_ONFAULT(r2)
	exit	[r2]
	ret	0

/* Two more fu/su routines .... for now ... just return -1. */
ENTRY(fuswintr)
ENTRY(suswintr)
	movqd -1, r0
	ret	0

/* C prototype:  copyin ( int *usrc, int *kdst, u_int i)  
   C prototype:  copyout ( int *ksrc, int *udst, u_int i) 

   i is the number of Bytes! to copy! 

   Similar code.... 
 */

ENTRY(copyout)
	enter	[r2,r3],0
# Check for copying priviledges!  i.e. copy on write!
	movd	B_ARG2, tos	/* Length */
	movd	B_ARG1, tos	/* adr */
	bsr	_check_user_write
	adjspb	-8
	cmpqd	0, r0
	bne	cifault
	br	docopy

ENTRY(copyin)
	enter	[r2,r3],0
docopy:
	movd	_curpcb(pc), r3
	addr	cifault(pc), PCB_ONFAULT(r3)
	movd	B_ARG2, r0	/* Length! */
	movd	B_ARG0, r1	/* Src adr */
	movd	B_ARG1, r2	/* Dst adr */
	movsb			/* Move it! */
	movqd	0, r0
	movqd	0, PCB_ONFAULT(r3)
	exit	[r2,r3]
	ret	0

cifault:
	movd	EFAULT, r0
	movd	_curpcb(pc), r3
	movqd	0, PCB_ONFAULT(r3)
	exit	[r2,r3]
	ret	0

/* setrunqueue: adds a process into a queue.  p->p_pri has a value between
 * 0 and 127.  By dividing by 4, it is shrunk into the 32 available queues.
 *
 * C calling prototype:  void setrunqueue (struct proc *p)
 *
 * Should be called at splhigh() and p->p_stat should be SRUN
 *
 */

ENTRY(setrunqueue)
	enter	[r2,r3,r4],0
	movd	B_ARG0, r2
	cmpqd	0, P_BACK(r2)		/* Items not on any list NULL-point */
	beq	set1
	addr	m_setrq(pc),tos		/* Was on the list! */
	bsr	_panic	
set1:
	movzbd	P_PRIORITY(r2),r3
	ashd	-2,r3
	sbitd	r3,_whichqs(pc)		/* set queue full */
	addr	_qs(pc)[r3:q], r3	/* get addr of qs entry */
	movd	P_BACK(r3),r4		/* get addr of last entry. */
	movd	P_FORW(r4), P_FORW(r2)  /* set p->p_forw */
	movd	r2, P_FORW(r4)		/* update tail's p_forw */
	movd    r4, P_BACK(r2)		/* set p->p_back */
	movd	r2, P_BACK(r3)		/* update qs ph_back */
	exit	[r2,r3,r4]
	ret	0

/* remrq: removes a process from a queue.  p->p_pri has a value between
 * 0 and 127.  By dividing by 4, it is shrunk into the 32 available queues.
 *
 * C calling prototype:  void remrq (struct proc *p)
 *
 * Should be called at splhigh()
 *
 */

ENTRY(remrq)
	enter	[r2,r3,r4,r5],0
	movd	B_ARG0, r2
	movzbd	P_PRIORITY(r2), r3
	ashd	-2, r3
	cbitd	r3, _whichqs(pc)	/* clear queue full */
	bfs	rem1

	addr	m_remrq(pc),tos		/* No queue entry! */
	bsr	_panic	
rem1:
	movd	P_FORW(r2),  r4		/* Addr of next item. */
	movd	P_BACK(r2), r5		/* Addr of prev item. */
	movd	r4, P_FORW(r5)		/* Unlink item. */
	movd	r5, P_BACK(r4)
	movqd	0, P_FORW(r2)		/* show not on queue. */
	movqd	0, P_BACK(r2)		/* show not on queue. */
	cmpd	r4, r5			/* r4 = r5 => empty queue */
	beq	rem2

	sbitd	r3, _whichqs(pc)		/* Restore whichqs bit. */

rem2:
	exit	[r2,r3,r4,r5]
	ret	0


/* Switch to another process from kernel code...  */

ENTRY(cpu_switch)
	ints_off	/* to make sure cpu_switch runs to completion. */
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],0
/*	addqd	1, _cnt+V_SWTCH(pc) 		*/

	movd	_curproc(pc), r0
	cmpqd	0, r0
	beq	sw1

	/* Save "kernel context" - - user context is saved at trap/svc.
	   Kernel registers are saved at entry to swtch. */

	movd	P_ADDR(r0), r0
	sprd	sp, PCB_KSP(r0)
	sprd	fp,  PCB_KFP(r0)
	smr	ptb0,  PCB_PTB(r0)

	/*  Save the Cur_pl.  */
	movd	Cur_pl(pc), PCB_PL(r0)

	movqd	0, _curproc(pc)		/* no current proc! */

sw1:	/* Get something from a Queue! */
	ints_off	/* Just in case we came from Idle. */
	movqd	0, r0
	ffsd	_whichqs(pc), r0
	bfs	Idle

	/* Get the process and unlink it from the queue. */
	addr	_qs(pc)[r0:q], r1	/* address of qs entry! */
	movd	0(r1), r2		/* get process pointer! */
	movd	P_FORW(r2), r3		/* get address of next entry. */

  /* Test code */
  cmpqd	0, r3
  bne notzero
  bsr _dump_qs
notzero:

	/* unlink the entry. */
	movd	r3, 0(r1)		/* New head pointer. */
	movd	r1, P_BACK(r3) 		/* New reverse pointer. */
	cmpd	r1, r3			/* Empty? */
	bne	restart

	/* queue is empty, turn off whichqs. */
	cbitd	r0, _whichqs(pc)

restart:	/* r2 has pointer to new proc.. */

	/* Reload the new kernel context ... r2 points to proc entry. */
	movqd	0, P_BACK(r2)		/* NULL p_forw */
	movqd	0, _want_resched(pc)	/* We did a resched! */
	movd	P_ADDR(r2), r3		/* get new pcb pointer */


	/* Do we need to reload floating point here? */

	lmr	ptb0, PCB_PTB(r3)
	lprd	sp, PCB_KSP(r3)
	lprd	fp, PCB_KFP(r3)
	movw	PCB_FLAGS(r3), r4	/* Get the flags. */

	movd	r2, _curproc(pc)
	movd	r3, _curpcb(pc)

	/* Restore the previous processor level. */
	movd	PCB_PL(r3), tos
	bsr	_splx
	adjspb  -4

	/* Return to the caller of swtch! */
	exit	[r0,r1,r2,r3,r4,r5,r6,r7]
	ret	0			

/*
 * The idle process!
 */
Idle:
	lprd	sp, KERN_INT_SP	/* Set up the "interrupt" stack. */
	movqd	0, r0
	ffsd	_whichqs(pc), r0
	bfc	sw1
	bsr	_spl0
	wait			/* Wait for interrupt. */
	br	sw1

m_setrq: .asciz "Setrunqueue problem!"
m_remrq: .asciz "Remrq problem!"

/* As part of the fork operation, we need to prepare a user are for 
   execution, to be resumed by swtch()...  

   C proto is low_level_fork (struct user *up)

   up is a pointer the the "user" struct in the child.
   We copy the kernel stack and  update the pcb of the child to
   return from low_level_fork twice.

   The first return should return a 0.  The "second" return should
   be because of a swtch() and should return a 1.

*/

ENTRY(low_level_fork)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],0

	/* Save "kernel context" - - user context is saved at trap/svc.
	   Kernel registers are saved at entry to swtch. */

	movd	B_ARG0, r2		/* Gets the paddr field of child. */
	sprd	sp, PCB_KSP(r2)
	sprd	fp,  PCB_KFP(r2)
	/* Don't save ptb0 because child has a different ptb0! */
	movd	Cur_pl(pc), PCB_PL(r2)

	/* Copy the kernel stack from this process to new stack. */
	addr	0(sp), r1	/* Source address */
	movd	r1, r3		/* Calculate the destination address */
	subd	USRSTACK, r3	/* Get the offset */
	addd	r3, r2		/* r2 had B_ARG0 in it.  now the dest addr */
	movd	r2, r5		/* Save the destination address */
	movd	KSTK_SIZE, r0	/* Calculate the length of the kernel stack. */
	subd	r3, r0

	movd	r0, r4		/* Check for a double alligned stack. */
	andd	3, r4
	cmpqd	0, r4
	beq	kcopy
	addr	m_ll_fork(pc),tos  /* panic if not double alligned. */
	bsr	_panic

kcopy:
	ashd	-2,r0		/* Divide by 4 to get # of doubles. */
	movsd			/* Copy the stack! */

	/* Set parent to return 0. */
	movqd	0,28(sp)

	/* Set child to return 1. */
	movqd	1,28(r5)

	exit	[r0,r1,r2,r3,r4,r5,r6,r7]
	ret	0

m_ll_fork: .asciz "_low_level_fork: kstack not double alligned."
	

/* Interrupt and trap processing. */
ENTRY(_trap_nvi)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	movqd	0, tos
	br	all_trap

ENTRY(_trap_nmi)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	movqd	1, tos
	br	all_trap

ENTRY(_trap_abt)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	movqd	2, tos
	smr 	tear, tos
	smr	msr, tos
	br	abt_trap

ENTRY(_trap_slave)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	movqd	3, tos
	br	all_trap

ENTRY(_trap_ill)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	movqd	4, tos
	br	all_trap

ENTRY(_trap_svc)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	lprd    sb, 0			/* for the kernel */

	/* Have an fpu? */
	cmpqd	0, __have_fpu(pc)
	beq	svc_no_fpu

	/* Save the FPU registers. */
	movd	_curpcb(pc), r3
	sfsr	PCB_FSR(r3)
	movl	f0,PCB_F0(r3)
	movl	f1,PCB_F1(r3)
	movl	f2,PCB_F2(r3)
	movl	f3,PCB_F3(r3)
	movl	f4,PCB_F4(r3)
	movl	f5,PCB_F5(r3)
	movl	f6,PCB_F6(r3)
	movl	f7,PCB_F7(r3)
	
	/* Call the system. */
	bsr	_syscall

	/* Restore the FPU registers. */
	movd	_curpcb(pc), r3
	lfsr	PCB_FSR(r3)
	movl	PCB_F0(r3),f0
	movl	PCB_F1(r3),f1
	movl	PCB_F2(r3),f2
	movl	PCB_F3(r3),f3
	movl	PCB_F4(r3),f4
	movl	PCB_F5(r3),f5
	movl	PCB_F6(r3),f6
	movl	PCB_F7(r3),f7

	/* Restore the usp and sb. */
	lprd	usp, REGS_USP(sp)
	lprd	sb, REGS_SB(sp)

	exit	[r0,r1,r2,r3,r4,r5,r6,r7]
	rett	0

svc_no_fpu:
	/* Call the system. */
	bsr	_syscall

	/* Restore the usp and sb. */
	lprd	usp, REGS_USP(sp)
	lprd	sb, REGS_SB(sp)

	exit	[r0,r1,r2,r3,r4,r5,r6,r7]
	rett	0

ENTRY(_trap_dvz)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	movqd	6, tos
	br	all_trap

ENTRY(_trap_flg)
	cinv	i, r0		/* Invalidate first line */
	addd	r1, r0
	cinv	i, r0		/* Invalidate possible second line */
	addqd	1, tos		/* Increment return address */
	rett	0

ENTRY(_trap_bpt)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	movd	8, tos
	br	all_trap

ENTRY(_trap_trc)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	movd	9, tos
	br	all_trap

ENTRY(_trap_und)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	movd	10, tos
	br	all_trap

ENTRY(_trap_rbe)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	movd	11, tos
	br	all_trap

ENTRY(_trap_nbe)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	movd	12, tos
	br	all_trap

ENTRY(_trap_ovf)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	movd	13, tos
	br	all_trap

ENTRY(_trap_dbg)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	movd	14, tos
	br	all_trap

ENTRY(_trap_reserved)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	movd	15, tos
all_trap:
	movqd	0,tos	/* Add 2 zeros for msr,tear in frame. */
	movqd	0,tos

abt_trap:
	lprd    sb, 0			/* for the kernel */

	/* Was this a real process? */
	cmpqd	0, _curproc(pc)
	beq	trap_no_fpu

	/* Have an fpu? */
	cmpqd	0, __have_fpu(pc)
	beq	trap_no_fpu

	/* Save the FPU registers. */
	movd	_curpcb(pc), r3		/* R3 is saved by gcc. */
	sfsr	PCB_FSR(r3)
	movl	f0,PCB_F0(r3)
	movl	f1,PCB_F1(r3)
	movl	f2,PCB_F2(r3)
	movl	f3,PCB_F3(r3)
	movl	f4,PCB_F4(r3)
	movl	f5,PCB_F5(r3)
	movl	f6,PCB_F6(r3)
	movl	f7,PCB_F7(r3)
	
	bsr _trap
	adjspb	-12	/* Pop off software part of trap frame. */

	/* Restore the FPU registers. */
	lfsr	PCB_FSR(r3)
	movl	PCB_F0(r3),f0
	movl	PCB_F1(r3),f1
	movl	PCB_F2(r3),f2
	movl	PCB_F3(r3),f3
	movl	PCB_F4(r3),f4
	movl	PCB_F5(r3),f5
	movl	PCB_F6(r3),f6
	movl	PCB_F7(r3),f7

	/* Reload the usp and sb just in case anything has changed. */
	lprd	usp, REGS_USP(sp)
	lprd	sb, REGS_SB(sp)

	exit	[r0,r1,r2,r3,r4,r5,r6,r7]
	rett  0

trap_no_fpu:
	bsr _trap
	adjspb	-12	/* Pop off software part of trap frame. */

	/* Reload the usp and sb just in case anything has changed. */
	lprd	usp, REGS_USP(sp)
	lprd	sb, REGS_SB(sp)

	exit	[r0,r1,r2,r3,r4,r5,r6,r7]
	rett  0

/* Interrupt service routines.... */

ENTRY(_int_clk)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	lprd    sb, 0			/* for the kernel */
	movd	Cur_pl(pc), tos
	movqd	0,tos
	addr	0(sp),tos	/* The address of the frame. */
	bsr	_hardclock
	cmpqd	0,tos		/* Remove the address of the frame. */
	br	exit_int

ENTRY(_int_scsi0)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	lprd    sb, 0			/* for the kernel */
	movd	Cur_pl(pc), tos
#if NAIC > 0
	movqd	0,tos
	bsr _aic_intr
#else
	movqd	5,tos
	bsr _bad_intr
#endif
	br	exit_int

ENTRY(_int_scsi1)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	movd	Cur_pl(pc), tos
#if NDP > 0
	movqd	1,tos
	bsr _dp_intr
#else
#if NNCR > 0
	movqd	1,tos
	bsr _ncr5380_intr
#else
	movqd	4,tos
	bsr _bad_intr
#endif
#endif
	br	exit_int

ENTRY(_int_uart0)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	lprd    sb, 0			/* for the kernel */
	movd	Cur_pl(pc), tos
	movqd	0,tos
	bsr _scnintr
	br	exit_int
ENTRY(_int_uart1)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	lprd    sb, 0			/* for the kernel */
	movd	Cur_pl(pc), tos
	movqd	1,tos
	bsr _scnintr
	br	exit_int
ENTRY(_int_uart2)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	lprd    sb, 0			/* for the kernel */
	movd	Cur_pl(pc), tos
	movqd	2,tos
	bsr _scnintr
	br	exit_int
ENTRY(_int_uart3)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	lprd    sb, 0			/* for the kernel */
	movd	Cur_pl(pc), tos
	movqd	3,tos
	bsr _scnintr
	br	exit_int
ENTRY(_int_bad)
	enter	[r0,r1,r2,r3,r4,r5,r6,r7],8
	sprd	usp, REGS_USP(sp)
	sprd	sb, REGS_SB(sp)
	lprd    sb, 0			/* for the kernel */
	movd	Cur_pl(pc), tos
	movqd	0,tos
	bsr _bad_intr

/* Common exit to all interrupt codes. */
exit_int:
	adjspb -8

	tbitw	8, REGS_PSR(sp)		/* In system mode? */
	bfs	do_user_intr		/* branch if yes! */

	lprd	usp, REGS_USP(sp)
	lprd	sb, REGS_SB(sp)
	exit	[r0,r1,r2,r3,r4,r5,r6,r7]
	reti

do_user_intr:

	/* Do "user" mode interrupt processing, including preemption. */
	ints_off
	movd	_curproc(pc), r2
	cmpqd	0,r2
	beq	intr_panic

	/* Have an fpu? */
	cmpqd	0, __have_fpu(pc)
	beq	intr_no_fpu

	/* Save the FPU registers. */
	movd	_curpcb(pc), r3		/* R3 is saved by gcc. */
	sfsr	PCB_FSR(r3)
	movl	f0,PCB_F0(r3)
	movl	f1,PCB_F1(r3)
	movl	f2,PCB_F2(r3)
	movl	f3,PCB_F3(r3)
	movl	f4,PCB_F4(r3)
	movl	f5,PCB_F5(r3)
	movl	f6,PCB_F6(r3)
	movl	f7,PCB_F7(r3)

intr_no_fpu:
	/* Do a reti to keep the icu happy. */
	sprw	psr, tos
	movqw 	0, tos		/* mod = 0 */
	addr	do_soft_intr(pc), tos
	reti

do_soft_intr:
	/* turn on interrupts! */
	ints_on

	/* Net processing */
	bsr	_splnet
	movd	r0, tos
	cmpqd	0, _want_softnet(pc)
	beq	no_net

#ifdef INET
#include "ether.h"
#if NETHER > 0
	DONET(NETISR_ARP, _arpintr)
#endif
	DONET(NETISR_IP, _ipintr)
#endif
#ifdef IMP
	DONET(NETISR_IMP, _impintr)
#endif
#ifdef NS
	DONET(NETISR_NS, _nsintr)
#endif
#ifdef ISO
	DONET(NETISR_ISO, _clnlintr)
#endif
#ifdef CCITT
	DONET(NETISR_CCITT, _ccittintr)
#endif
	movqd	0, _want_softnet(pc)
	movqd	0, _netisr(pc)

no_net:
	/* Run with interrupts on. */
	bsr	_splx
	movd	tos, r0

	cmpqd	0, _want_softclock(pc)
	beq	no_soft
	bsr	_splsoftclock
	movd	r0, tos		/* save the pl */
	bsr	_softclock
	movqd	0, _want_softclock(pc)
	bsr	_splx		/* parameter is alread on the stack. */
	movd	tos, r0		/* pop the parameter. */
	
no_soft:
	cmpqd	0, _want_resched(pc)
	beq	do_usr_ret
	movd	18, tos
	movqd	0,tos
	movqd	0,tos
	bsr _trap
	adjspb	-12	/* Pop off software part of trap frame. */

do_usr_ret:
	bsr	_spl0

	/* Have an fpu? */
	cmpqd	0, __have_fpu(pc)
	beq	intr_ret_no_fpu

	/* Restore the FPU registers.  r3 should be as set before. */
	lfsr	PCB_FSR(r3)
	movl	PCB_F0(r3),f0
	movl	PCB_F1(r3),f1
	movl	PCB_F2(r3),f2
	movl	PCB_F3(r3),f3
	movl	PCB_F4(r3),f4
	movl	PCB_F5(r3),f5
	movl	PCB_F6(r3),f6
	movl	PCB_F7(r3),f7

intr_ret_no_fpu:
	lprd	usp, REGS_USP(sp)
	lprd	sb, REGS_SB(sp)
	exit	[r0,r1,r2,r3,r4,r5,r6,r7]
	rett	0

intr_panic:
	addr	intr_panic_msg(pc),tos  /* panic if not double alligned. */
	bsr	_panic

intr_panic_msg:
	.asciz "user mode interrupt with no current process!"


/* ICU support.  The assembly routines for the PC532 ICU. */
		
ENTRY(splnet)
	ints_off
	save	[r1]
	movd	Cur_pl(pc), r0
	movd	r0,r1
	ord	_PL_net(pc), r1
	movw	r1, @ICU_ADR+IMSK
	movd	r1, Cur_pl(pc)
	restore [r1]
	ints_on
	ret	0

ENTRY(splimp)
	ints_off
	save	[r1]
	movd	Cur_pl(pc), r0
	movd	r0, r1
	ord	SPL_IMP, r1
	movw	r1, @ICU_ADR+IMSK
	movd	r1, Cur_pl(pc)
	restore [r1]
	ints_on
	ret	0

ENTRY(splsoftclock)
	ints_off
	save	[r1]
	movd	Cur_pl(pc), r0
	movd	r0, r1
	ord	SPL_SOFTCLK, r1
	movd	r1, Cur_pl(pc)
	restore [r1]
	ints_on
	ret	0

ENTRY(splbio)
	ints_off
	save	[r1]
	movd	Cur_pl(pc), r0
	movd	r0, r1
	ord	_PL_bio(pc), r1
	movw	r1, @ICU_ADR+IMSK
	movd	r1, Cur_pl(pc)
	restore [r1]
	ints_on
	ret	0

ENTRY(splclock)
ENTRY(splstatclock)
	ints_off
	save	[r1]
	movd	Cur_pl(pc), r0
	movd	r0, r1
	ord	SPL_CLK, r1
	movw	r1, @ICU_ADR+IMSK
	movd	r1, Cur_pl(pc)
	restore [r1]
	ints_on 
	ret 0

ENTRY(spltty)
	ints_off
	save	[r1]
	movd	Cur_pl(pc), r0
	movd	r0, r1
	ord	_PL_tty(pc), r1
	movw	r1, @ICU_ADR+IMSK
	movd	r1, Cur_pl(pc)
	restore [r1]
	ints_on
	ret 0

ENTRY(splhigh)			/* Just turn off interrupts! */
	ints_off
	movd	Cur_pl(pc), r0
	ret 0
	

ENTRY(splx)
	ints_off
	movd	S_ARG0, r0
	save	[r1]
	comd	_PL_zero(pc), r1
	cmpd	r1, r0			/* Going to level 0 is special. */
	beq	do_spl0

	movw	r0, @ICU_ADR+IMSK
	movd	r0, Cur_pl(pc)
	restore [r1]
	ints_on
	ret 0

ENTRY(splnone)
ENTRY(spl0)
	ints_off
	save	[r1]
do_spl0:
	comd	_PL_zero(pc), r1
	ord	SPL_NET, r1
	movw	r1, @ICU_ADR+IMSK
	movd	r1, Cur_pl(pc)
	ints_on

	/* Now for the network software interrupts. */

	cmpqd	0, _want_softnet(pc)
	beq	no_net1

#ifdef INET
#if NETHER > 0
	DONET(NETISR_ARP, _arpintr)
#endif
	DONET(NETISR_IP, _ipintr)
#endif
#ifdef IMP
	DONET(NETISR_IMP, _impintr)
#endif
#ifdef NS
	DONET(NETISR_NS, _nsintr)
#endif
#ifdef ISO
	DONET(NETISR_ISO, _clnlintr)
#endif
#ifdef CCITT
	DONET(NETISR_CCITT, _ccittintr)
#endif
	movqd	0, _want_softnet(pc)
	movqd	0, _netisr(pc)

no_net1:
	ints_off
	comd	_PL_zero(pc), r1
	movw	r1, @ICU_ADR+IMSK
	movd	r1, Cur_pl(pc)
	restore [r1]
	ints_on

	ret 0

/* Include all other .s files. */
#include "bcopy.s"
#include "bzero.s"


/* pmap support??? ..... */

/*
 * Note: This version greatly munged to avoid various assembler errors
 * that may be fixed in newer versions of gas. Perhaps newer versions
 * will have more pleasant appearance.
 */

	.set	IDXSHIFT,10
	.set	SYSTEM,0xFE000000	# virtual address of system start
	/*note: gas copys sign bit (e.g. arithmetic >>), can't do SYSTEM>>22! */
	.set	SYSPDROFF,0x3F8		# Page dir index of System Base

/*
 * PTmap is recursive pagemap at top of virtual address space.
 * Within PTmap, the page directory can be found (third indirection).
 */
#define PDRPDROFF	0x03F7	/* page dir index of page dir */
	.globl	_PTmap, _PTD, _PTDpde, _Sysmap
	.set	_PTmap,0xFDC00000
	.set	_PTD,0xFDFF7000
	.set	_Sysmap,0xFDFF8000
	.set	_PTDpde,0xFDFF7000+4*PDRPDROFF

/*
 * APTmap, APTD is the alternate recursive pagemap.
 * It's used when modifying another process's page tables.
 */
#define APDRPDROFF	0x03FE	/* page dir index of page dir */
	.globl	_APTmap, _APTD, _APTDpde
	.set	_APTmap,0xFF800000
	.set	_APTD,0xFFBFE000
	.set	_APTDpde,0xFDFF7000+4*APDRPDROFF

/*
 * Access to each processes kernel stack is via a region of
 * per-process address space (at the beginning), immediatly above
 * the user process stack.
 */
#if 0
	.set	_kstack, USRSTACK
	.globl	_kstack
#endif
	.set	PPDROFF,0x3F6
	.set	PPTEOFF,0x400-UPAGES	# 0x3FE

.data
.globl _PDRPDROFF
_PDRPDROFF:
	.long PDRPDROFF

/* Some bogus data, to keep vmstat happy, for now. */
	.globl	_intrnames, _eintrnames, _intrcnt, _eintrcnt
_intrnames:
_eintrnames:
_intrcnt:
_eintrcnt:
	.long	0
