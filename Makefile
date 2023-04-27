.PHONY: all build disass clean
all: build disass
build:
	mkdir -p out
	gcc main.c -o out/safe -fcf-protection=none
	gcc main.c -o out/unsafe -fno-stack-protector -fcf-protection=none
	ddisasm out/unsafe --ir out/unsafe.gtirb
	python3 add_canary.py out/unsafe.gtirb out/canary.gtirb
	gtirb-pprinter out/canary.gtirb --binary out/canary

disass:
	objdump -dj .text out/safe -M intel > out/disass-safe
	objdump -dj .text out/unsafe -M intel > out/disass-unsafe
	objdump -dj .text out/canary -M intel > out/disass-canary

clean:
	rm -f out/safe out/unsafe out/canary 
	rm -f out/unsafe.gtirb out/canary.gtirb
	rm -f out/disass-safe out/disass-unsafe out/disass-canary
