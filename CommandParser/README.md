# CommandParser
This project is about implementing the Command line interface in C for Developer custom C aplications. Developer can integrate the library with the application and registered his own customized commands to Interact with the application. 
The CLI interface is in the form of library, hence, only one process is supported at a time. Currently, the communication between CLI interface and backend application is through callbacks. We shall extend this project to establish IPC between CLI interface and backend process. The CLI interface has support for show,debug,clear,config commands a developer can register. Library authenticate the command format and values,  and if the cmd entered is one of the format of the registered command, the application registered callback for that command is triggered. Config command negation is also supported. On pressing "?", it also displays the list of feasible next suboptions to the user with help string. 

This Project gives developer Linux like command like interface to interact with the application. This project closesly emulate the Routing devices interactive CLI shell.

See The testapp.c to learn the usage of the library.
#include libcli.h and cmdtlv.h in your application to use the library.
Compile your application by linking it with libcli.a library using -lcli. See Makefile for help.

Steps :

1. Run 'make' to compile the library.
2. Run test aplication executable (./exe) and enjoy the CLI.

TODO:
1. To place the validation checks for supported data types


How to make use of this Library in your projects :
=====================================================
See the doc LinuxLikeCommandLineInterface.docx present along with the src code.
