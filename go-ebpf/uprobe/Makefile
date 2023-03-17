uprobe.bpf.o: uprobe.bpf.c
	clang \
		-target bpf \
		-I/usr/include/x86_64-linux-gnu \
		-g \
		-O2 \
		-o $@ \
		-c $^

.PHONY: run

run:
	nm /usr/local/pgsql/bin/postgres | awk '$2=="t" || $2=="T" {print $3}' |  sudo go run uprobe.go
