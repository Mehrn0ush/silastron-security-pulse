.PHONY: test validate preview

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

validate:
	PYTHONPATH=src python3 -m silastron_pulse validate preview/data/manifest.json
	PYTHONPATH=src python3 -m silastron_pulse validate public/data/manifest.json

preview:
	python3 -m http.server 8080 --directory preview
