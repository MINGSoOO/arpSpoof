all:arp_spoof

arp_spoof: func.o main.o
	g++ -o arp_spoof func.o main.o -lpcap

func.o: func.cpp my_spoof.h
	g++ -c -o func.o func.cpp -lpcap

main.o: main.cpp my_spoof.h
	g++ -c -o main.o main.cpp

clean:
	rm -f *.o 
	rm -f arp_spoof
