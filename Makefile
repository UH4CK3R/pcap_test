pcap_test: pcap_test.o
	g++ -o pcap_test pcap_test.o -lpcap

pcap_test.o: pcap_test.c
	g++ -c -o pcap_test.o pcap_test.c

clean: 
	rm -f *.o pcap_test
