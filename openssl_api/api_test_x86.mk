export CROSS_COMPILE = 
export SYS_ROOT =
export CFLAGS = -O2 -Wall -s -D_GNU_SOURCE -I$(SYS_ROOT)/usr/include
export LDFLAGS = 

export CC = $(CROSS_COMPILE)gcc
export CXX = $(CROSS_COMPILE)g++
export AS = $(CROSS_COMPILE)as

EXEC = crypto_envelope_x86 crypto_parsekey_x86 crypto_pkcs7_envelope_x86

all: $(EXEC)

crypto_envelope_x86:crypto_envelope.c
	$(CC) $(LDFLAGS) -o $@ $^ -lcrypto

crypto_parsekey_x86:crypto_parse_key.c
	$(CC) $(LDFLAGS) -o $@ $^ -lcrypto

crypto_pkcs7_envelope_x86:crypto_pkcs7_envelope.c
	$(CC) $(LDFLAGS) -o $@ $^ -lcrypto

clean:
	-rm -f $(EXEC) *.elf *.gdb *.a
