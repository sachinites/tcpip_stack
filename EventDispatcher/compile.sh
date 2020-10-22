rm *.o
rm *exe
gcc -g -c event_dispatcher.c -o event_dispatcher.o
gcc -g -c main.c -o main.o
gcc -g -c ../gluethread/glthread.c -o ../gluethread/glthread.o
gcc -g -c main_pkt_q.c -o main_pkt_q.o
gcc -g -c main_mixed.c -o main_mixed.o
gcc -g main.o event_dispatcher.o ../gluethread/glthread.o -o exe -lpthread
gcc -g event_dispatcher.o ../gluethread/glthread.o main_pkt_q.o -o main_pkt_q.exe -lpthread
gcc -g event_dispatcher.o ../gluethread/glthread.o main_mixed.o -o main_mixed.exe -lpthread
