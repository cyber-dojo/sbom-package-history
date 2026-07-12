# Makefile for sbom-package-history.

.PHONY: cares_demo

# Run the c-ares supersession demo against the live aws-prod environment.
cares_demo:
	./bin/cares_demo
