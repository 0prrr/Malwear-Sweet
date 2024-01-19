ENTRY := woohoo
OUTPUT_NAME := whatever
CCRSRC := ~/Devil/lib/llvmingw281123-1706-bsd-x86_64/bin/x86_64-w64-mingw32-windres
CC := ~/Devil/lib/llvmingw281123-1706-bsd-x86_64/bin/x86_64-w64-mingw32-gcc
OPENSSL := openssl
SIGNING := osslsigncode

CFLAGS := -Wno-everything -Wl,--subsystem,console -Os -s -D_DEBUG -fno-exceptions -fno-stack-protector -fno-PIE -D_FORTIFY_SOURCE=0 -nodefaultlibs -nostdlib -luser32 -lkernel32 -e$(ENTRY)

OPENSSLFLAGS := req -x509 -nodes -days 365 -newkey rsa:2048 -keyout mal.key -out mal.crt

# for linux systems, use date -d "dd/mm/yyyy hh:mm:ss" +"%s" instead to get unix epoch time
SIGNFLAGS := sign -certs ./mal.crt -key ./mal.key -n "$(OUTPUT_NAME)" -i https://$(OUTPUT_NAME).io -time `date -j -f "%Y-%m-%d %H:%M:%S" "2018-03-13 09:13:33" "+%s"` -in $(OUTPUT_NAME).exe -out $(OUTPUT_NAME).signed.exe

RSRC := *.rc
SRC := *.c *.o

RSRC_TARGET := resource.o
EXE_TARGET := $(OUTPUT_NAME).exe
EXE_TARGET_SIGNED := $(OUTPUT_NAME).signed.exe

CRT_FILE := mal.crt

all: clean $(EXE_TARGET) $(RSRC_TARGET)

$(EXE_TARGET): $(RSRC_TARGET)
	@@echo "[*]Compiling executable ..."
	@@echo ""
	$(CC) $(CFLAGS) $(SRC) -o $@ $^
	if [ ! -f $(CRT_FILE) ]; then $(OPENSSL) $(OPENSSLFLAGS); fi
	if [ -f $(EXE_TARGET_SIGNED) ]; then rm -rf $(EXE_TARGET_SIGNED); fi
	$(SIGNING) $(SIGNFLAGS)
	chmod +x $(EXE_TARGET_SIGNED)

$(RSRC_TARGET):
	@@echo "[*]Compiling resource file ..."
	@@echo ""
	$(CCRSRC) $(RSRC) -o $(RSRC_TARGET)
	@@echo ""

clean:
	rm -rf *.o

