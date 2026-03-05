# LSA Whisperer BOF - Makefile for Adaptix C2
# Cross-compile from Linux using MinGW
#
# Prerequisites:
#   apt install mingw-w64
#
# Usage:
#   make all      - Build all BOF modules
#   make msv1_0   - Build MSV1_0 module only
#   make kerberos - Build Kerberos module only
#   make cloudap  - Build CloudAP module only
#   make clean    - Remove build artifacts

CC64 = x86_64-w64-mingw32-gcc
CC86 = i686-w64-mingw32-gcc
STRIP64 = x86_64-w64-mingw32-strip --strip-unneeded
STRIP86 = i686-w64-mingw32-strip --strip-unneeded

# BOF compilation flags
CFLAGS = -c -Os -DBOF -Wall -Wno-unused-variable -Wno-unused-function -w
INCLUDES = -I ../_include -I include -I src/common

OUTDIR = _bin

.PHONY: all msv1_0 kerberos cloudap clean

all: msv1_0 kerberos cloudap

# MSV1_0 Module (DPAPI cred key, NTLMv1 generation)
msv1_0:
	@mkdir -p $(OUTDIR)
	@($(CC64) $(CFLAGS) $(INCLUDES) -o $(OUTDIR)/msv1_0_bof.x64.o src/msv1_0/msv1_0_bof.c && $(STRIP64) $(OUTDIR)/msv1_0_bof.x64.o) && echo '[+] msv1_0_bof (x64)' || echo '[!] msv1_0_bof (x64)'
	@($(CC86) $(CFLAGS) $(INCLUDES) -o $(OUTDIR)/msv1_0_bof.x86.o src/msv1_0/msv1_0_bof.c && $(STRIP86) $(OUTDIR)/msv1_0_bof.x86.o) && echo '[+] msv1_0_bof (x86)' || echo '[!] msv1_0_bof (x86)'

# Kerberos Module (klist, dump, purge)
kerberos:
	@mkdir -p $(OUTDIR)
	@($(CC64) $(CFLAGS) $(INCLUDES) -o $(OUTDIR)/kerberos_bof.x64.o src/kerberos/kerberos_bof.c && $(STRIP64) $(OUTDIR)/kerberos_bof.x64.o) && echo '[+] kerberos_bof (x64)' || echo '[!] kerberos_bof (x64)'
	@($(CC86) $(CFLAGS) $(INCLUDES) -o $(OUTDIR)/kerberos_bof.x86.o src/kerberos/kerberos_bof.c && $(STRIP86) $(OUTDIR)/kerberos_bof.x86.o) && echo '[+] kerberos_bof (x86)' || echo '[!] kerberos_bof (x86)'

# CloudAP Module (SSO cookies, cloud info)
cloudap:
	@mkdir -p $(OUTDIR)
	@($(CC64) $(CFLAGS) $(INCLUDES) -o $(OUTDIR)/cloudap_bof.x64.o src/cloudap/cloudap_bof.c && $(STRIP64) $(OUTDIR)/cloudap_bof.x64.o) && echo '[+] cloudap_bof (x64)' || echo '[!] cloudap_bof (x64)'
	@($(CC86) $(CFLAGS) $(INCLUDES) -o $(OUTDIR)/cloudap_bof.x86.o src/cloudap/cloudap_bof.c && $(STRIP86) $(OUTDIR)/cloudap_bof.x86.o) && echo '[+] cloudap_bof (x86)' || echo '[!] cloudap_bof (x86)'

clean:
	rm -rf $(OUTDIR)
