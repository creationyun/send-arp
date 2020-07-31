LDLIBS=-lpcap

all: send-arp

send-arp: net-address.o protocol-hdr.o main.o
	$(LINK.cc) $^ $(LDLIBS) -o $@

clean:
	rm -f send-arp *.o
