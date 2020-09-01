all: pcap-analysis

pcap-analysis: pcap.o
	g++ -o pcap-analysis pcap.o -lpcap

main.o:
	g++ -c pcap.o pcap.cpp

clean:
	rm -rf pcap-analysis *.o
