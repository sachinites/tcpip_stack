# tcpip_stack
Implement your own TCP IP Stack

what is the output of "file test.exe" on your machine ? My output is below :
vm@ubuntu:~/Documents/orig/tcpip_stack$ file test.exe
test.exe: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=35c72703d60f1f0bb551e1eb17d5d9f392152d1f, for GNU/Linux 3.2.0, with debug_info, not stripped

Confirm that, your's also shows  x86-64 or is it something else.

What is your machien architecture ? Mine is x86_64.
vm@ubuntu:~/Documents/orig/tcpip_stack$ uname -a
Linux ubuntu 5.0.0-36-generic #39-Ubuntu SMP Tue Nov 12 09:46:06 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
vm@ubuntu:~/Documents/orig/tcpip_stack$

I think the problem is, project is being compiled for x86-64 machines, but your machine is ARM. So you need to build the project as per your machine architecture.

Do the below steps :

Install gcc for ARM architecture machines !

sudo apt-get install gcc-arm-linux-gnueabi

If in the output you see ARM instead of x86-64, which I think is the case most probably, then do the following :

1. Open Makefile of the project, and replace the first line :
CC=gcc
to
CC=arm-linux-gnueabi-gcc

2. add -f flag to all rm commands.
rm -f <whatever is here>

3. Do same changes of step 1 and 2 in CommandParser/Makefile also.

4. run the command : 
make cleanall ; make all

5. run ./test.exe

I have added file MakefileARM and CommandParser/MakefileARM to the project with commit code : 26a4b3518aef82604825565269a4f08517cc2985
a. rename Makefile and CommandParser/Makefile to Makefilex86 and CommandParser/Makefilex86 repectively.
b. rename MakefileARM and CommandParser/MakefileARM to Makefile and CommandParser/Makefile
c. do : make cleanall; make all
