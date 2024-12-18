# Default CFLAGS
CFLAGS := -Wall -masm=intel -static -std=c2x

# Check if the compiler is gcc or clang
ifneq (,$(filter $(notdir $(CC)),gcc cc))
# CFLAGS += 
else
ifeq ($(notdir $(CC)),clang)
# CFLAGS += 
endif
endif

all: exploit


userfault: userfault.c
	$(CC) $(CFLAGS) -c userfault.c

exploit: userfault
	$(CC) $(CFLAGS) -o rootfs/$@ exp.c *.o

compress: exploit
	cd rootfs && \
	find . -print0 \
	| cpio --null -ov --format=newc -R root \
	| gzip -9 > rootfs.cpio.gz && \
	mv ./rootfs.cpio.gz ../

decompress:
	mkdir -p rootfs && \
	cd rootfs && \
	cp ../rootfs.cpio.gz . && \
	gunzip ./rootfs.cpio.gz && \
	cpio -idm < ./rootfs.cpio && \
	rm rootfs.cpio

clean:
	rm -f rootfs/exploit
