all: spoofer sniffer

spoofer:
	gcc spoofer.c -o spoofer
sniffer:
	gcc sniffer.c -o sniffer -lpcap
snoffer:
	gcc snoffer.c -o snoffer -lpcap


clean: 
	rm -rf *.o spoofer sniffer