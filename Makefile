nfqueue:
	gcc -o nfqueue-test nfqueue-test.c -lnetfilter_queue
	./nfqueue-test

dns:
	gcc -o nfqueue-dns dns.h dns.c nfqueue-dns.c -lnetfilter_queue
