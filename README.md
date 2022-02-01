Motivation
==========

I use NetBSD 1.0 source code as a reference to poke around 4.4 BSD-Lite TCP/IP implementation. The source code can be compiled into i386 arch and the binary is runnable in Qemu.

The TCP/IP stack is in `usr/src/sys/netinet`. The total lines of source code is `13,936`.

How
===

To compile and run the kernel from source, 

1. Download [VM from here](https://sourceforge.net/projects/bsd42/files/4BSD%20under%20Windows/v0.4/NetBSD%201.0.zip/download).
1. Run VM in Qemu by using the script below.
1. Telnet to `localhost 20023`
1. login as `root` with `vt200` emulated terminal.
1. cd `/usr/src/sys/arch/i386/conf` and modify config `QEMU`. Run `config QEMU`.
1. cd `/usr/src/sys/arch/i386/compile/QEMU` and run `make depend;make`
1. copy the compiled kernel `netbsd` to root `/`
1. reboot.


- Qemu script

```
qemu-system-i386 \
 -hda netbsd-1.0.vmdk \
 -netdev user,id=net0,hostfwd=tcp::20023-:23\
 -device ne2k_isa,netdev=net0,irq=10,iobase=0x320 \
 -m 64 \
 -no-reboot \
 -rtc base=localtime \
 -k en-us
```


