# tcpip_stack project.
Implement your own TCP IP Stack in userspace.

In this course, We shall be implementing a Working TCP/IP Stack through several Networking Projects. Below is the list of projects Implemented so far.

Visit : www.csepracticals.com for more projects and courses.

## Project 1 : Build a MultiNode Topology Emulation of Routers and Switches

## Project 2 : Implement DataLink Layer (L2 routing), including ARP

## Project 3 : Implement L2 Switching (Mac-based Learning and Forwarding)

## Project 4 : Implement Vlan Based Mac learning and Forwarding

## Project 5 : Implement Network Layer (L3 routing)

## Project 6 : Implement Access Control List from Scratch

## Project 7 : Implement Prefix List for Route Selection & Import / Export Policies

## Project 8 : Implement support for Network Object Groups

## Project 9 : Implement a prototype of a routing protocol ( IGP )

## Project 10 : GRE Tunnel Support

## Project 11 : SRV6 Control Plane and Data Plane Implemented. End Fn Supported : END, END-X

#### After Doing These Projects, you shall be able to :

Tell why you need Data link layer and Network Layer
How to design a new Application protocol on a TCP/IP stack (just like ICMP, HTTP, etc all work on TCP/IP Stack)
Get your hands dirty with industry-level network programming.
Learn cooking up, parsing and reading the packet buffers
Understand End-To-End Architecture and Design of Network Application and TCP/IP Stack
Conquer Interviews for the role of Network Developer Engineer
Decorate your GitHub, and add a strong project to your HAT, Expected LOCs of this course shall exceed 70k !
This project will fill up the gap between theoretical knowledge and the Implementation version of it. How does it sound that you have written code by your own hands to resolve ARP, packet forwarding, etc. Decorate your resume and GitHub with this project.

# How to Build and Run: 

## Steps to build the Project : 

This project depends on several standard, and private libraries. Therefore, we we describe the steps to resolve all dependencies and eventually build the project executable. OS supported is Linux. MAC with Apple Silicon, not supported.

Make sure you have C++ compiler and Makefile utility installed in your system. If not install them as below:  
`sudo apt-get install g++`  
`sudo apt-get install make`


Installation of standard libraries:  
1. `sudo apt-get install libpq-dev`        # For PostgresSQL client interface
2. `sudo apt-get install libncurses5-dev`  # For ncurses library
3. `sudo apt-get install libfl-dev`     	 # For flex library, used for parsing

Rest of the standard libraries are installed by default on any linux distro which are listed below. So you need  
not take any action to install them on your linux system.  
4. `pthread`  
5. `rt`  
6. `m` (math library)  


Once you have downloaded this project (assuming in your home dir) , your home dir will have a folder called `tcpip_stack`.  Switch to branch `DCB` first using below commands in your terminal.  

`cd tcpip_stack`  
`git checkout DCB`  


Installation of private libraries. These libraries are implemented to support this project. Below libraries are 
already downloaded along with the src code. You need not take any action for these. These will be compiled and 
linked with the project during compilation.
1. CLIBuilder
2. LinuxMemoryManager
3. FSMImplementation
4. FireWall
5. glthread (linked list)
6. libtimer (wheel timer)
7. EventDispatcher (Event loop scheduler)
8. BitOp / bitmaps (bitmap)
9. mtire (longest prefix match data structure)
10. stack (stack)
11. hashmap (hashmap)
12. prefix-list (prefix list)
13. c-hashtable (hashtable)
14. Tracer (Tracer)

Installation of private external libraries. Some libraries are build separately. These include :
1. MathExpressionParser
2. RDBMSImplementation (This library is dependent on MathExpressionParser)

Pls follow the below steps : 
Assuming you have downloaded this project in your home directory. Download the below libraries in your home directory as well  (as the same level as this project), follow the below steps in your terminal.

git clone https://github.com/sachinites/MathExpressionParser.git  
`cd MathExpressionParser`  
`git checkout Oops`  


git clone https://github.com/sachinites/RDBMSImplementation.git  
`cd RDBMSImplementation`  
`git checkout DCB`  

After above steps, you home directory should have following 3 dir : 
`tcpip_stack (this project)`   `MathExpressionParser`    `RDBMSImplementation`

### Continue to follow below steps : 

### compile MathExpressionParser library first 
`cd MathExpressionParser`  
`sh compile.sh`

### compile RDBMSImplementation library next
`cd RDBMSImplementation/SqlParser`  
`make all`

### Now, final step is to compile tcpip_stack project
`cd tcpip_stack`  
`make all`  

### Once you have successfully compiled the project, you will see 2 executables in the same directory.
1. tcpstack.exe
2. pkt_gen.exe

### To run the project, you need to run tcpstack.exe.
`./tcpstack.exe`  

### To terminate the project, use command "run terminate" in the CLI prompt of the project.
`Soft-Firewall>$ run term`

Thats it . Enjoy the project. If you make any changes in tcpip_stack dir (main project), you need to rebuild only tcpip_stack project.
if you make any changes in external private libraries (MathExpressionParser/RDBMSImplementation), then rebuild the library, followed by rebuilding the tcpip_stack project.


Last updated : 14 Mar 2025
( Miss you Maa !! )
