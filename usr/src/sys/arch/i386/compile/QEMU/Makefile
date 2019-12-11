KERN_IDENT=GENERICAHA
IDENT=-DGENERICAHA -DI586_CPU -DI486_CPU -DI386_CPU -DGENERIC -DMACHINE_NONCONTIG -DCOMPAT_09 -DCOMPAT_NOMID -DMATH_EMULATE -DSCSI -DKERNFS -DMSDOSFS -DUCONSOLE -DXSERVER -DTCP_COMPAT_42 -DCOMPAT_43 -DNFSCLIENT -DCD9660 -DINET -DFFS -DDEVPAGER -DVNODEPAGER -DSWAPPAGER
PARAM=-DTIMEZONE=480 -DDST=1 -DMAXUSERS=10
# 	from: @(#)Makefile.hp300	8.2 (Berkeley) 1/23/94
#	$Id: Makefile.i386,v 1.45 1994/06/15 16:46:39 mycroft Exp $
#
# Makefile for NetBSD
#
# This makefile is constructed from a machine description:
#	config machineid
# Most changes should be made in the machine description
#	/sys/arch/i386/conf/``machineid''
# after which you should do
#	 config machineid
# Generic makefile changes should be made in
#	/sys/arch/i386/conf/Makefile.i386
# after which config should be rerun for all machines of that type.
#
# N.B.: NO DEPENDENCIES ON FOLLOWING FLAGS ARE VISIBLE TO MAKEFILE
#	IF YOU CHANGE THE DEFINITION OF ANY OF THESE RECOMPILE EVERYTHING
#
# -DTRACE	compile in kernel tracing hooks
# -DQUOTA	compile in file system quotas
#


# DEBUG is set to -g by config if debugging is requested (config -g).
# PROF is set to -pg by config if profiling is requested (config -p).
AS=	as ${DEBUG}
CC=	cc ${DEBUG}
CPP=	cpp
LD=	ld
TOUCH=	touch -f -c
AWK=	awk

# source tree is located via $S relative to the compilation directory
S=	../../../..
I386=	../..

INCLUDES= -I. -I$S/arch -I$S -I$S/sys
COPTS=	${INCLUDES} ${IDENT} -DKERNEL -Di386
CFLAGS=	-O6 ${COPTS}
LOAD_ADDRESS= F8100000

### find out what to use for libkern
.include "$S/lib/libkern/Makefile.inc"
.ifndef PROF
LIBKERN=	${KERNLIB}
.else
LIBKERN=	${KERNLIB_PROF}
.endif

# compile rules: rules are named ${TYPE}_${SUFFIX}${CONFIG_DEP}
# where TYPE is NORMAL, DRIVER, or PROFILE}; SUFFIX is the file suffix,
# capitalized (e.g. C for a .c file), and CONFIG_DEP is _C if the file
# is marked as config-dependent.

NORMAL_C=	${CC} -c ${CFLAGS} ${PROF} $<
NORMAL_C_C=	${CC} -c ${CFLAGS} ${PROF} ${PARAM} $<

DRIVER_C=	${CC} -c ${CFLAGS} ${PROF} $<
DRIVER_C_C=	${CC} -c ${CFLAGS} ${PROF} ${PARAM} $<

PROFILE_C=	${CC} -S -c ${CFLAGS} $< ; \
		sed -e s/_mcount/mcount/ -e s/subrmcount/subr_mcount/ <$*.s | \
		${AS} -o $@; \
		rm -f $*.s

NORMAL_S=	${CPP} -DLOCORE ${COPTS} $< | ${AS} -o $@
NORMAL_S_C=	${CPP} -DLOCORE ${COPTS} ${PARAM} $< | ${AS} -o $@

OBJS=cd9660_bmap.o cd9660_lookup.o cd9660_node.o cd9660_rrip.o \
	cd9660_util.o cd9660_vfsops.o cd9660_vnops.o exec_aout.o \
	exec_conf.o exec_script.o exec_subr.o init_main.o init_sysent.o \
	kern_acct.o kern_clock.o kern_descrip.o kern_exec.o kern_exit.o \
	kern_fork.o kern_malloc.o kern_physio.o kern_proc.o kern_prot.o \
	kern_resource.o kern_sig.o kern_subr.o kern_synch.o \
	kern_sysctl.o kern_time.o kern_xxx.o subr_disk.o subr_log.o \
	subr_prf.o subr_prof.o subr_rmap.o subr_xxx.o sys_generic.o \
	sys_process.o sys_socket.o tty.o tty_compat.o tty_conf.o \
	tty_pty.o tty_subr.o tty_tty.o uipc_domain.o uipc_mbuf.o \
	uipc_proto.o uipc_socket.o uipc_socket2.o uipc_syscalls.o \
	uipc_usrreq.o vfs_bio.o vfs_cache.o vfs_cluster.o vfs_conf.o \
	vfs_init.o vfs_lockf.o vfs_lookup.o vfs_subr.o vfs_syscalls.o \
	vfs_vnops.o dead_vnops.o kernfs_vfsops.o kernfs_vnops.o \
	procfs_fpregs.o procfs_mem.o procfs_regs.o spec_vnops.o \
	msdosfs_conv.o msdosfs_denode.o msdosfs_fat.o msdosfs_lookup.o \
	msdosfs_vfsops.o msdosfs_vnops.o if.o if_ethersubr.o if_loop.o \
	if_sl.o radix.o raw_cb.o raw_usrreq.o route.o rtsock.o \
	slcompress.o if_ether.o igmp.o in.o in_pcb.o in_proto.o \
	ip_icmp.o ip_input.o ip_mroute.o ip_output.o raw_ip.o \
	tcp_debug.o tcp_input.o tcp_output.o tcp_subr.o tcp_timer.o \
	tcp_usrreq.o udp_usrreq.o krpc_subr.o nfs_bio.o nfs_boot.o \
	nfs_node.o nfs_nqlease.o nfs_socket.o nfs_subs.o nfs_syscalls.o \
	nfs_vfsops.o nfs_vnops.o ffs_alloc.o ffs_balloc.o ffs_inode.o \
	ffs_subr.o ffs_tables.o ffs_vfsops.o ffs_vnops.o ufs_bmap.o \
	ufs_ihash.o ufs_inode.o ufs_lookup.o ufs_vfsops.o ufs_vnops.o \
	device_pager.o kern_lock.o swap_pager.o vm_fault.o vm_glue.o \
	vm_init.o vm_kern.o vm_map.o vm_meter.o vm_mmap.o vm_object.o \
	vm_page.o vm_pageout.o vm_pager.o vm_swap.o vm_unix.o vm_user.o \
	vnode_pager.o autoconf.o conf.o disksubr.o in_cksum.o machdep.o \
	math_emulate.o mem.o microtime.o pmap.o process_machdep.o \
	random.o sys_machdep.o trap.o vm_machdep.o clock.o com.o dma.o \
	fd.o if_ed.o intr.o isa.o lpt.o npx.o pccons.o spkr.o wd.o pci.o \
	pci_machdep.o cons.o scsi_base.o scsi_ioctl.o scsiconf.o 

CFILES=$S/isofs/cd9660/cd9660_bmap.c $S/isofs/cd9660/cd9660_lookup.c \
	$S/isofs/cd9660/cd9660_node.c $S/isofs/cd9660/cd9660_rrip.c \
	$S/isofs/cd9660/cd9660_util.c $S/isofs/cd9660/cd9660_vfsops.c \
	$S/isofs/cd9660/cd9660_vnops.c $S/kern/exec_aout.c \
	$S/kern/exec_conf.c $S/kern/exec_script.c $S/kern/exec_subr.c \
	$S/kern/init_main.c $S/kern/init_sysent.c $S/kern/kern_acct.c \
	$S/kern/kern_clock.c $S/kern/kern_descrip.c $S/kern/kern_exec.c \
	$S/kern/kern_exit.c $S/kern/kern_fork.c $S/kern/kern_malloc.c \
	$S/kern/kern_physio.c $S/kern/kern_proc.c $S/kern/kern_prot.c \
	$S/kern/kern_resource.c $S/kern/kern_sig.c $S/kern/kern_subr.c \
	$S/kern/kern_synch.c $S/kern/kern_sysctl.c $S/kern/kern_time.c \
	$S/kern/kern_xxx.c $S/kern/subr_disk.c $S/kern/subr_log.c \
	$S/kern/subr_prf.c $S/kern/subr_prof.c $S/kern/subr_rmap.c \
	$S/kern/subr_xxx.c $S/kern/sys_generic.c $S/kern/sys_process.c \
	$S/kern/sys_socket.c $S/kern/tty.c $S/kern/tty_compat.c \
	$S/kern/tty_conf.c $S/kern/tty_pty.c $S/kern/tty_subr.c \
	$S/kern/tty_tty.c $S/kern/uipc_domain.c $S/kern/uipc_mbuf.c \
	$S/kern/uipc_proto.c $S/kern/uipc_socket.c \
	$S/kern/uipc_socket2.c $S/kern/uipc_syscalls.c \
	$S/kern/uipc_usrreq.c $S/kern/vfs_bio.c $S/kern/vfs_cache.c \
	$S/kern/vfs_cluster.c $S/kern/vfs_conf.c $S/kern/vfs_init.c \
	$S/kern/vfs_lockf.c $S/kern/vfs_lookup.c $S/kern/vfs_subr.c \
	$S/kern/vfs_syscalls.c $S/kern/vfs_vnops.c \
	$S/miscfs/deadfs/dead_vnops.c $S/miscfs/kernfs/kernfs_vfsops.c \
	$S/miscfs/kernfs/kernfs_vnops.c $S/miscfs/procfs/procfs_fpregs.c \
	$S/miscfs/procfs/procfs_mem.c $S/miscfs/procfs/procfs_regs.c \
	$S/miscfs/specfs/spec_vnops.c $S/msdosfs/msdosfs_conv.c \
	$S/msdosfs/msdosfs_denode.c $S/msdosfs/msdosfs_fat.c \
	$S/msdosfs/msdosfs_lookup.c $S/msdosfs/msdosfs_vfsops.c \
	$S/msdosfs/msdosfs_vnops.c $S/net/if.c $S/net/if_ethersubr.c \
	$S/net/if_loop.c $S/net/if_sl.c $S/net/radix.c $S/net/raw_cb.c \
	$S/net/raw_usrreq.c $S/net/route.c $S/net/rtsock.c \
	$S/net/slcompress.c $S/netinet/if_ether.c $S/netinet/igmp.c \
	$S/netinet/in.c $S/netinet/in_pcb.c $S/netinet/in_proto.c \
	$S/netinet/ip_icmp.c $S/netinet/ip_input.c \
	$S/netinet/ip_mroute.c $S/netinet/ip_output.c \
	$S/netinet/raw_ip.c $S/netinet/tcp_debug.c \
	$S/netinet/tcp_input.c $S/netinet/tcp_output.c \
	$S/netinet/tcp_subr.c $S/netinet/tcp_timer.c \
	$S/netinet/tcp_usrreq.c $S/netinet/udp_usrreq.c \
	$S/nfs/krpc_subr.c $S/nfs/nfs_bio.c $S/nfs/nfs_boot.c \
	$S/nfs/nfs_node.c $S/nfs/nfs_nqlease.c $S/nfs/nfs_socket.c \
	$S/nfs/nfs_subs.c $S/nfs/nfs_syscalls.c $S/nfs/nfs_vfsops.c \
	$S/nfs/nfs_vnops.c $S/ufs/ffs/ffs_alloc.c \
	$S/ufs/ffs/ffs_balloc.c $S/ufs/ffs/ffs_inode.c \
	$S/ufs/ffs/ffs_subr.c $S/ufs/ffs/ffs_tables.c \
	$S/ufs/ffs/ffs_vfsops.c $S/ufs/ffs/ffs_vnops.c \
	$S/ufs/ufs/ufs_bmap.c $S/ufs/ufs/ufs_ihash.c \
	$S/ufs/ufs/ufs_inode.c $S/ufs/ufs/ufs_lookup.c \
	$S/ufs/ufs/ufs_vfsops.c $S/ufs/ufs/ufs_vnops.c \
	$S/vm/device_pager.c $S/vm/kern_lock.c $S/vm/swap_pager.c \
	$S/vm/vm_fault.c $S/vm/vm_glue.c $S/vm/vm_init.c $S/vm/vm_kern.c \
	$S/vm/vm_map.c $S/vm/vm_meter.c $S/vm/vm_mmap.c \
	$S/vm/vm_object.c $S/vm/vm_page.c $S/vm/vm_pageout.c \
	$S/vm/vm_pager.c $S/vm/vm_swap.c $S/vm/vm_unix.c $S/vm/vm_user.c \
	$S/vm/vnode_pager.c $S/arch/i386/i386/autoconf.c \
	$S/arch/i386/i386/conf.c $S/arch/i386/i386/disksubr.c \
	$S/arch/i386/i386/in_cksum.c $S/arch/i386/i386/machdep.c \
	$S/arch/i386/i386/math_emulate.c $S/arch/i386/i386/mem.c \
	$S/arch/i386/i386/pmap.c $S/arch/i386/i386/process_machdep.c \
	$S/arch/i386/i386/sys_machdep.c $S/arch/i386/i386/trap.c \
	$S/arch/i386/i386/vm_machdep.c $S/arch/i386/isa/clock.c \
	$S/arch/i386/isa/com.c $S/arch/i386/isa/dma.c \
	$S/arch/i386/isa/fd.c $S/arch/i386/isa/if_ed.c \
	$S/arch/i386/isa/intr.c $S/arch/i386/isa/isa.c \
	$S/arch/i386/isa/lpt.c $S/arch/i386/isa/npx.c \
	$S/arch/i386/isa/pccons.c $S/arch/i386/isa/spkr.c \
	$S/arch/i386/isa/wd.c $S/arch/i386/pci/pci.c \
	$S/arch/i386/pci/pci_machdep.c $S/dev/cons.c $S/scsi/scsi_base.c \
	$S/scsi/scsi_ioctl.c $S/scsi/scsiconf.c $S/arch/i386/i386/swapgeneric.c 

# load lines for config "xxx" will be emitted as:
# xxx: ${SYSTEM_DEP} swapxxx.o
#	${SYSTEM_LD_HEAD}
#	${SYSTEM_LD} swapxxx.o
#	${SYSTEM_LD_TAIL}
SYSTEM_OBJ=	locore.o vnode_if.o ${OBJS} param.o ioconf.o ${LIBKERN}
SYSTEM_DEP=	Makefile ${SYSTEM_OBJ}
SYSTEM_LD_HEAD=	rm -f $@
SYSTEM_LD=	-@if [ X${DEBUG} = X-g ]; \
		then strip=-X; \
		else strip=-x; \
		fi; \
		echo ${LD} $$strip -z -T ${LOAD_ADDRESS} -o $@ -e start '$${SYSTEM_OBJ}' vers.o; \
		${LD} $$strip -z -T ${LOAD_ADDRESS} -o $@ -e start ${SYSTEM_OBJ} vers.o
SYSTEM_LD_TAIL=	@size $@; chmod 755 $@; \
		[ X${DEBUG} = X-g ] && { \
		echo cp $@ $@.gdb; rm -f $@.gdb; cp $@ $@.gdb; \
		echo strip -d $@; strip -d $@; } || true

SYSTEM_SWAP_DEP+= swapgeneric.o
netbsd: ${SYSTEM_DEP} swapgeneric.o vers.o
	${SYSTEM_LD_HEAD}
	${SYSTEM_LD} swapgeneric.o
	${SYSTEM_LD_TAIL}

swapgeneric.o: ../../i386/swapgeneric.c
	${NORMAL_C}

all: netbsd

vers.o: ${SYSTEM_DEP} ${SYSTEM_SWAP_DEP}
	sh $S/conf/newvers.sh
	${CC} ${CFLAGS} -c vers.c

clean:
	rm -f eddep *netbsd netbsd.gdb tags *.o locore.i [a-z]*.s \
		[Ee]rrs linterrs makelinks

lint: /tmp param.c
	@lint -hbxn -DGENERIC -Dvolatile= ${COPTS} ${PARAM} -UKGDB \
	    ${I386}/i386/Locore.c ${CFILES} ${I386}/i386/swapgeneric.c \
	    ioconf.c param.c | \
	    grep -v 'struct/union .* never defined' | \
	    grep -v 'possible pointer alignment problem'

locore.o: assym.s ${I386}/i386/locore.s machine/trap.h machine/psl.h
locore.o: machine/pte.h ${I386}/isa/vector.s ${I386}/isa/icu.s
locore.o: $S/sys/errno.h machine/specialreg.h ${I386}/isa/debug.h
locore.o: ${I386}/isa/icu.h ${I386}/isa/isa.h vector.h $S/net/netisr.h
	${CPP} -DLOCORE ${COPTS} ${I386}/i386/locore.s | ${AS} -o locore.o

# the following is necessary because autoconf.o depends on #if GENERIC
autoconf.o: Makefile

# the following are necessary because the files depend on the types of
# cpu's included in the system configuration
locore.o machdep.o: Makefile

# depend on network or filesystem configuration
uipc_proto.o vfs_conf.o locore.o: Makefile

# depend on maxusers
assym.s: Makefile

# depends on KDB (cons.o also depends on GENERIC)
trap.o cons.o: Makefile

assym.s: genassym
	./genassym >assym.s

genassym: ${I386}/i386/genassym.c
	${CC} ${INCLUDES} ${IDENT} ${PARAM} -Di386 -o genassym \
	    ${I386}/i386/genassym.c

depend: assym.s param.c vnode_if.h
	mkdep ${COPTS} ${CFILES} ioconf.c param.c
	mkdep -a -p ${INCLUDES} ${IDENT} ${PARAM} ${I386}/i386/genassym.c

links:
	egrep '#if' ${CFILES} | sed -f $S/conf/defines | \
	  sed -e 's/:.*//' -e 's/\.c/.o/' | sort -u > dontlink
	echo ${CFILES} | tr -s ' ' '\12' | sed 's/\.c/.o/' | \
	  sort -u | comm -23 - dontlink | \
	  sed 's,../.*/\(.*.o\),rm -f \1;ln -s ../GENERIC/\1 \1,' > makelinks
	sh makelinks && rm -f dontlink

tags:
	@echo "see $S/kern/Makefile for tags"

ioconf.o: ioconf.c
	${CC} -c ${CFLAGS} ioconf.c

param.c: $S/conf/param.c
	rm -f param.c
	cp $S/conf/param.c .

param.o: param.c Makefile
	${CC} -c ${CFLAGS} ${PARAM} param.c

vnode_if.c vnode_if.h: $S/kern/vnode_if.sh $S/kern/vnode_if.src
	AWK="${AWK}" sh $S/kern/vnode_if.sh $S/kern/vnode_if.src

cd9660_bmap.o: $S/isofs/cd9660/cd9660_bmap.c
	${NORMAL_C}

cd9660_lookup.o: $S/isofs/cd9660/cd9660_lookup.c
	${NORMAL_C}

cd9660_node.o: $S/isofs/cd9660/cd9660_node.c
	${NORMAL_C}

cd9660_rrip.o: $S/isofs/cd9660/cd9660_rrip.c
	${NORMAL_C}

cd9660_util.o: $S/isofs/cd9660/cd9660_util.c
	${NORMAL_C}

cd9660_vfsops.o: $S/isofs/cd9660/cd9660_vfsops.c
	${NORMAL_C}

cd9660_vnops.o: $S/isofs/cd9660/cd9660_vnops.c
	${NORMAL_C}

exec_aout.o: $S/kern/exec_aout.c
	${NORMAL_C}

exec_conf.o: $S/kern/exec_conf.c
	${NORMAL_C}

exec_script.o: $S/kern/exec_script.c
	${NORMAL_C}

exec_subr.o: $S/kern/exec_subr.c
	${NORMAL_C}

init_main.o: $S/kern/init_main.c
	${NORMAL_C}

init_sysent.o: $S/kern/init_sysent.c
	${NORMAL_C}

kern_acct.o: $S/kern/kern_acct.c
	${NORMAL_C}

kern_clock.o: $S/kern/kern_clock.c
	${NORMAL_C}

kern_descrip.o: $S/kern/kern_descrip.c
	${NORMAL_C}

kern_exec.o: $S/kern/kern_exec.c
	${NORMAL_C}

kern_exit.o: $S/kern/kern_exit.c
	${NORMAL_C}

kern_fork.o: $S/kern/kern_fork.c
	${NORMAL_C}

kern_malloc.o: $S/kern/kern_malloc.c
	${NORMAL_C}

kern_physio.o: $S/kern/kern_physio.c
	${NORMAL_C}

kern_proc.o: $S/kern/kern_proc.c
	${NORMAL_C}

kern_prot.o: $S/kern/kern_prot.c
	${NORMAL_C}

kern_resource.o: $S/kern/kern_resource.c
	${NORMAL_C}

kern_sig.o: $S/kern/kern_sig.c
	${NORMAL_C}

kern_subr.o: $S/kern/kern_subr.c
	${NORMAL_C}

kern_synch.o: $S/kern/kern_synch.c
	${NORMAL_C}

kern_sysctl.o: $S/kern/kern_sysctl.c
	${NORMAL_C}

kern_time.o: $S/kern/kern_time.c
	${NORMAL_C}

kern_xxx.o: $S/kern/kern_xxx.c
	${NORMAL_C}

subr_disk.o: $S/kern/subr_disk.c
	${NORMAL_C}

subr_log.o: $S/kern/subr_log.c
	${NORMAL_C}

subr_prf.o: $S/kern/subr_prf.c
	${NORMAL_C}

subr_prof.o: $S/kern/subr_prof.c
	${NORMAL_C}

subr_rmap.o: $S/kern/subr_rmap.c
	${NORMAL_C}

subr_xxx.o: $S/kern/subr_xxx.c
	${NORMAL_C}

sys_generic.o: $S/kern/sys_generic.c
	${NORMAL_C}

sys_process.o: $S/kern/sys_process.c
	${NORMAL_C}

sys_socket.o: $S/kern/sys_socket.c
	${NORMAL_C}

tty.o: $S/kern/tty.c
	${NORMAL_C}

tty_compat.o: $S/kern/tty_compat.c
	${NORMAL_C}

tty_conf.o: $S/kern/tty_conf.c
	${NORMAL_C}

tty_pty.o: $S/kern/tty_pty.c
	${NORMAL_C}

tty_subr.o: $S/kern/tty_subr.c
	${NORMAL_C}

tty_tty.o: $S/kern/tty_tty.c
	${NORMAL_C}

uipc_domain.o: $S/kern/uipc_domain.c
	${NORMAL_C}

uipc_mbuf.o: $S/kern/uipc_mbuf.c
	${NORMAL_C}

uipc_proto.o: $S/kern/uipc_proto.c
	${NORMAL_C}

uipc_socket.o: $S/kern/uipc_socket.c
	${NORMAL_C}

uipc_socket2.o: $S/kern/uipc_socket2.c
	${NORMAL_C}

uipc_syscalls.o: $S/kern/uipc_syscalls.c
	${NORMAL_C}

uipc_usrreq.o: $S/kern/uipc_usrreq.c
	${NORMAL_C}

vfs_bio.o: $S/kern/vfs_bio.c
	${NORMAL_C}

vfs_cache.o: $S/kern/vfs_cache.c
	${NORMAL_C}

vfs_cluster.o: $S/kern/vfs_cluster.c
	${NORMAL_C}

vfs_conf.o: $S/kern/vfs_conf.c
	${NORMAL_C}

vfs_init.o: $S/kern/vfs_init.c
	${NORMAL_C}

vfs_lockf.o: $S/kern/vfs_lockf.c
	${NORMAL_C}

vfs_lookup.o: $S/kern/vfs_lookup.c
	${NORMAL_C}

vfs_subr.o: $S/kern/vfs_subr.c
	${NORMAL_C}

vfs_syscalls.o: $S/kern/vfs_syscalls.c
	${NORMAL_C}

vfs_vnops.o: $S/kern/vfs_vnops.c
	${NORMAL_C}

dead_vnops.o: $S/miscfs/deadfs/dead_vnops.c
	${NORMAL_C}

kernfs_vfsops.o: $S/miscfs/kernfs/kernfs_vfsops.c
	${NORMAL_C}

kernfs_vnops.o: $S/miscfs/kernfs/kernfs_vnops.c
	${NORMAL_C}

procfs_fpregs.o: $S/miscfs/procfs/procfs_fpregs.c
	${NORMAL_C}

procfs_mem.o: $S/miscfs/procfs/procfs_mem.c
	${NORMAL_C}

procfs_regs.o: $S/miscfs/procfs/procfs_regs.c
	${NORMAL_C}

spec_vnops.o: $S/miscfs/specfs/spec_vnops.c
	${NORMAL_C}

msdosfs_conv.o: $S/msdosfs/msdosfs_conv.c
	${NORMAL_C}

msdosfs_denode.o: $S/msdosfs/msdosfs_denode.c
	${NORMAL_C}

msdosfs_fat.o: $S/msdosfs/msdosfs_fat.c
	${NORMAL_C}

msdosfs_lookup.o: $S/msdosfs/msdosfs_lookup.c
	${NORMAL_C}

msdosfs_vfsops.o: $S/msdosfs/msdosfs_vfsops.c
	${NORMAL_C}

msdosfs_vnops.o: $S/msdosfs/msdosfs_vnops.c
	${NORMAL_C}

if.o: $S/net/if.c
	${NORMAL_C}

if_ethersubr.o: $S/net/if_ethersubr.c
	${NORMAL_C}

if_loop.o: $S/net/if_loop.c
	${NORMAL_C}

if_sl.o: $S/net/if_sl.c
	${NORMAL_C}

radix.o: $S/net/radix.c
	${NORMAL_C}

raw_cb.o: $S/net/raw_cb.c
	${NORMAL_C}

raw_usrreq.o: $S/net/raw_usrreq.c
	${NORMAL_C}

route.o: $S/net/route.c
	${NORMAL_C}

rtsock.o: $S/net/rtsock.c
	${NORMAL_C}

slcompress.o: $S/net/slcompress.c
	${NORMAL_C}

if_ether.o: $S/netinet/if_ether.c
	${NORMAL_C}

igmp.o: $S/netinet/igmp.c
	${NORMAL_C}

in.o: $S/netinet/in.c
	${NORMAL_C}

in_pcb.o: $S/netinet/in_pcb.c
	${NORMAL_C}

in_proto.o: $S/netinet/in_proto.c
	${NORMAL_C}

ip_icmp.o: $S/netinet/ip_icmp.c
	${NORMAL_C}

ip_input.o: $S/netinet/ip_input.c
	${NORMAL_C}

ip_mroute.o: $S/netinet/ip_mroute.c
	${NORMAL_C}

ip_output.o: $S/netinet/ip_output.c
	${NORMAL_C}

raw_ip.o: $S/netinet/raw_ip.c
	${NORMAL_C}

tcp_debug.o: $S/netinet/tcp_debug.c
	${NORMAL_C}

tcp_input.o: $S/netinet/tcp_input.c
	${NORMAL_C}

tcp_output.o: $S/netinet/tcp_output.c
	${NORMAL_C}

tcp_subr.o: $S/netinet/tcp_subr.c
	${NORMAL_C}

tcp_timer.o: $S/netinet/tcp_timer.c
	${NORMAL_C}

tcp_usrreq.o: $S/netinet/tcp_usrreq.c
	${NORMAL_C}

udp_usrreq.o: $S/netinet/udp_usrreq.c
	${NORMAL_C}

krpc_subr.o: $S/nfs/krpc_subr.c
	${NORMAL_C}

nfs_bio.o: $S/nfs/nfs_bio.c
	${NORMAL_C}

nfs_boot.o: $S/nfs/nfs_boot.c
	${NORMAL_C}

nfs_node.o: $S/nfs/nfs_node.c
	${NORMAL_C}

nfs_nqlease.o: $S/nfs/nfs_nqlease.c
	${NORMAL_C}

nfs_socket.o: $S/nfs/nfs_socket.c
	${NORMAL_C}

nfs_subs.o: $S/nfs/nfs_subs.c
	${NORMAL_C}

nfs_syscalls.o: $S/nfs/nfs_syscalls.c
	${NORMAL_C}

nfs_vfsops.o: $S/nfs/nfs_vfsops.c
	${NORMAL_C}

nfs_vnops.o: $S/nfs/nfs_vnops.c
	${NORMAL_C}

ffs_alloc.o: $S/ufs/ffs/ffs_alloc.c
	${NORMAL_C}

ffs_balloc.o: $S/ufs/ffs/ffs_balloc.c
	${NORMAL_C}

ffs_inode.o: $S/ufs/ffs/ffs_inode.c
	${NORMAL_C}

ffs_subr.o: $S/ufs/ffs/ffs_subr.c
	${NORMAL_C}

ffs_tables.o: $S/ufs/ffs/ffs_tables.c
	${NORMAL_C}

ffs_vfsops.o: $S/ufs/ffs/ffs_vfsops.c
	${NORMAL_C}

ffs_vnops.o: $S/ufs/ffs/ffs_vnops.c
	${NORMAL_C}

ufs_bmap.o: $S/ufs/ufs/ufs_bmap.c
	${NORMAL_C}

ufs_ihash.o: $S/ufs/ufs/ufs_ihash.c
	${NORMAL_C}

ufs_inode.o: $S/ufs/ufs/ufs_inode.c
	${NORMAL_C}

ufs_lookup.o: $S/ufs/ufs/ufs_lookup.c
	${NORMAL_C}

ufs_vfsops.o: $S/ufs/ufs/ufs_vfsops.c
	${NORMAL_C}

ufs_vnops.o: $S/ufs/ufs/ufs_vnops.c
	${NORMAL_C}

device_pager.o: $S/vm/device_pager.c
	${NORMAL_C}

kern_lock.o: $S/vm/kern_lock.c
	${NORMAL_C}

swap_pager.o: $S/vm/swap_pager.c
	${NORMAL_C}

vm_fault.o: $S/vm/vm_fault.c
	${NORMAL_C}

vm_glue.o: $S/vm/vm_glue.c
	${NORMAL_C}

vm_init.o: $S/vm/vm_init.c
	${NORMAL_C}

vm_kern.o: $S/vm/vm_kern.c
	${NORMAL_C}

vm_map.o: $S/vm/vm_map.c
	${NORMAL_C}

vm_meter.o: $S/vm/vm_meter.c
	${NORMAL_C}

vm_mmap.o: $S/vm/vm_mmap.c
	${NORMAL_C}

vm_object.o: $S/vm/vm_object.c
	${NORMAL_C}

vm_page.o: $S/vm/vm_page.c
	${NORMAL_C}

vm_pageout.o: $S/vm/vm_pageout.c
	${NORMAL_C}

vm_pager.o: $S/vm/vm_pager.c
	${NORMAL_C}

vm_swap.o: $S/vm/vm_swap.c
	${NORMAL_C}

vm_unix.o: $S/vm/vm_unix.c
	${NORMAL_C}

vm_user.o: $S/vm/vm_user.c
	${NORMAL_C}

vnode_pager.o: $S/vm/vnode_pager.c
	${NORMAL_C}

autoconf.o: $S/arch/i386/i386/autoconf.c
	${NORMAL_C}

conf.o: $S/arch/i386/i386/conf.c
	${NORMAL_C}

disksubr.o: $S/arch/i386/i386/disksubr.c
	${NORMAL_C}

in_cksum.o: $S/arch/i386/i386/in_cksum.c
	${NORMAL_C}

machdep.o: $S/arch/i386/i386/machdep.c
	${NORMAL_C_C}

math_emulate.o: $S/arch/i386/i386/math_emulate.c
	${NORMAL_C}

mem.o: $S/arch/i386/i386/mem.c
	${NORMAL_C}

microtime.o: $S/arch/i386/i386/microtime.s
	${NORMAL_S}

pmap.o: $S/arch/i386/i386/pmap.c
	${NORMAL_C}

process_machdep.o: $S/arch/i386/i386/process_machdep.c
	${NORMAL_C}

random.o: $S/arch/i386/i386/random.s
	${NORMAL_S}

sys_machdep.o: $S/arch/i386/i386/sys_machdep.c
	${NORMAL_C}

trap.o: $S/arch/i386/i386/trap.c
	${NORMAL_C}

vm_machdep.o: $S/arch/i386/i386/vm_machdep.c
	${NORMAL_C}

clock.o: $S/arch/i386/isa/clock.c
	${NORMAL_C}

com.o: $S/arch/i386/isa/com.c
	${NORMAL_C}

dma.o: $S/arch/i386/isa/dma.c
	${NORMAL_C}

fd.o: $S/arch/i386/isa/fd.c
	${NORMAL_C}

if_ed.o: $S/arch/i386/isa/if_ed.c
	${NORMAL_C}

intr.o: $S/arch/i386/isa/intr.c
	${NORMAL_C}

isa.o: $S/arch/i386/isa/isa.c
	${NORMAL_C}

lpt.o: $S/arch/i386/isa/lpt.c
	${NORMAL_C}

npx.o: $S/arch/i386/isa/npx.c
	${NORMAL_C}

pccons.o: $S/arch/i386/isa/pccons.c
	${NORMAL_C}

spkr.o: $S/arch/i386/isa/spkr.c
	${NORMAL_C}

wd.o: $S/arch/i386/isa/wd.c
	${NORMAL_C}

pci.o: $S/arch/i386/pci/pci.c
	${NORMAL_C}

pci_machdep.o: $S/arch/i386/pci/pci_machdep.c
	${NORMAL_C}

cons.o: $S/dev/cons.c
	${NORMAL_C}

scsi_base.o: $S/scsi/scsi_base.c
	${NORMAL_C}

scsi_ioctl.o: $S/scsi/scsi_ioctl.c
	${NORMAL_C}

scsiconf.o: $S/scsi/scsiconf.c
	${NORMAL_C}

