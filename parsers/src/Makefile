compile:
	gcc -o nfqueue-dns dns.h dns.c nfqueue-dns.c -lnetfilter_queue

test: compile
	gcc -o test dns.h dns.c test.c

run: clean compile
	sudo nft -f ../../firewall.nft
	./nfqueue-dns

clean:
	sudo nft flush table nft-test
	rm -f nfqueue-dns
