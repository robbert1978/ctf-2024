# Default CFLAGS
CFLAGS := -Wall -masm=intel -D_FILE_OFFSET_BITS=64 -static -pthread -lfuse -ldl

# Check if the compiler is gcc or clang
ifneq (,$(filter $(notdir $(CC)),gcc cc))
# CFLAGS += 
else
ifeq ($(notdir $(CC)),clang)
# CFLAGS += 
endif
endif

all: exploit

exploit: exp.c
	$(CC) -o $@ $^ $(CFLAGS)

compress: exploit
	sudo mount -o loop root.img root ; \
	sudo cp exploit root/ && \
	sudo umount root

clean:
	rm -f initramfs/exploit
