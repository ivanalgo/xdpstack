all: tcp_xdp.o

tcp_xdp.o: tcp_xdp.c
	 clang -O2 -g -Wall -target bpf -c tcp_xdp.c -o tcp_xdp.o

clean:
	rm -rf tcp_xdp.o

install:
	/usr/sbin/ip link set lo xdp object tcp_xdp.o sec xdp

uninstall:
	/usr/sbin/ip link set dev lo xdp off

test:
	tcpdump -i lo  -v  tcp -c 10 -nn &
	sleep 1
	echo > /sys/kernel/debug/tracing/trace
	sleep 1
	-nc localhost 8080
	cat /sys/kernel/debug/tracing/trace
  
