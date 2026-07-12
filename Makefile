# Makefile for sbom-package-history.

.PHONY: cares_text_demo test

# Run the c-ares supersession demo (text output) against the live aws-prod environment.
cares_text_demo:
	./bin/cares_text_demo

# Run the unit test suite.
test:
	python3 -m pytest
