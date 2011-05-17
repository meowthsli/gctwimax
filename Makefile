ALL=wimax

all: $(ALL)

ifndef CC
CC=gcc
endif

ifndef LDO
LDO=$(CC)
endif

CONFDIR = /usr/share/gctwimax

FLAGS = -MMD -O2 -g -Wall

FLAGS += -I.
FLAGS += -I/usr/include
FLAGS += -I/usr/include/eap_peer
FLAGS += -I/usr/include/dbus-1.0
FLAGS += -I/usr/lib/dbus-1.0/include
FLAGS += -I/usr/include/glib-2.0
FLAGS += -I/usr/lib/glib-2.0/include

FLAGS += -DEAP_TLS
FLAGS += -DEAP_TTLS
FLAGS += -DEAP_MD5
FLAGS += -DEAP_CHAP
FLAGS += -DEAP_MSCHAPv2
 
FLAGS += -DCONFDIR="$(CONFDIR)"

FLAGS += -DIEEE8021X_EAPOL

override CFLAGS += $(FLAGS)

OBJS_ex = src/wimax.o src/protocol.o src/logging.o src/tap_dev.o src/eap_auth.o

wimax: $(OBJS_ex)
	$(LDO) $(LDFLAGS) -o gctwimax $(OBJS_ex) -leap -lusb-1.0 -lglib-2.0 -ldbus-glib-1 -lcrypto -lz

install:
	cp ./gctwimax /usr/bin/gctwimax

	if [ ! -d $(CONFDIR) ] ; then mkdir $(CONFDIR) ; fi
	cp ./src/event.sh $(CONFDIR)/event.sh ;

uninstall:
	rm /usr/bin/gctwimax
	rm $(CONFDIR)/event.sh

.PHONY: clean
clean:
#	$(MAKE) -C . clean
	rm -f core src/*~ src/*.o src/*.d $(ALL)

-include $(OBJS:%.o=%.d)
