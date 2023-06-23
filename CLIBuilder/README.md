# CLIBuilder
Build Cisco like Command Line Interface 

Just run the shell script compile.sh. It will create test executables which you can run and play with CLIs. 
testapp.cpp and main4.cpp are application files which makes use of LIBCLI library to implement custom CLIs.

compile.sh
=============
g++ -g -c string_util.c -o string_util.o -fpermissive
g++ -g -c -I serializer serializer/serialize.c -o serializer/serialize.o -fpermissive
g++ -g -c -I stack stack/stack.c -o stack/stack.o -fpermissive
g++ -g -c -I . KeyProcessor/KeyProcessor.cpp -o KeyProcessor/KeyProcessor.o
g++ -g -c -I . CmdTree/CmdTree.cpp -o CmdTree/CmdTree.o
g++ -g -c -I . CmdTree/clistd.cpp -o CmdTree/clistd.o
g++ -g -c -I . CmdTree/CmdTreeCursor.cpp -o CmdTree/CmdTreeCursor.o
g++ -g -c -I . gluethread/glthread.c -o gluethread/glthread.o
g++ -g -c -I . app.cpp -o app.o
g++ -g -c -I . main4.c -o main4.o
g++ -g -c -I . testapp.c -o testapp.o -fpermissive
g++ -g -c printf_hijack.cpp -o printf_hijack.o
g++ -g app.o string_util.o serializer/serialize.o  stack/stack.o KeyProcessor/KeyProcessor.o CmdTree/CmdTree.o CmdTree/clistd.o gluethread/glthread.o CmdTree/CmdTreeCursor.o -o exe -lncurses
g++ -g main4.o string_util.o serializer/serialize.o stack/stack.o KeyProcessor/KeyProcessor.o CmdTree/CmdTree.o CmdTree/clistd.o gluethread/glthread.o CmdTree/CmdTreeCursor.o -o main4.exe -lncurses
g++ -g testapp.o string_util.o serializer/serialize.o stack/stack.o KeyProcessor/KeyProcessor.o CmdTree/CmdTree.o CmdTree/clistd.o gluethread/glthread.o CmdTree/CmdTreeCursor.o -o testapp.exe -lncurses
ar rs libclibuilder.a string_util.o serializer/serialize.o  stack/stack.o KeyProcessor/KeyProcessor.o CmdTree/CmdTree.o CmdTree/clistd.o gluethread/glthread.o CmdTree/CmdTreeCursor.o

Dependency :
Make sure you have** ncurses** library installed on your system.
To install ncurses, **sudo apt-get install ncurses-dev**

Highlighting features :
=============================
1. work with C and C++ applications.
2. Developed on linux, may work on windows also but not tested.
3. Auto-completions.
4. CLI history is maintained.
5. '?' Display next set of possible options
6. '.' show command completions
7. use 'show help' command to know more after running the executable.
