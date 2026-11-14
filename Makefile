build:
	chmod +x bin/dmarc-report

test:
	raco test tests/test.rkt

sample: build
	mkdir -p docs site
	./bin/dmarc-report examples/reports > docs/sample-output.txt; true
	./bin/dmarc-report examples/reports --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "dmarc-report" "Reads DMARC aggregate (rua) XML reports and tells you who is spoofing you and what breaks if you enforce. Racket." "Synthetic reports for example.test from invented receivers, using documentation IP ranges."
