LDLIBS += -lpcap

all: deauth-attack

airodump: deauth-attack.cpp

clean:
	rm -f deauth-attack *.o

