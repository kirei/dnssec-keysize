

root.hints:
	curl -o $@ https://www.internic.net/domain/named.root

clean:
	rm -f root.hints
