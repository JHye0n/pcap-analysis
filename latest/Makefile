LDLIBS=-lpcap

all: pcap-analysis

pcap-analysis: pcap.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -g

clean:
	rm -rf pcap-analysis *.o
