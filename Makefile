PYTHON=python3

.NOTPARALLEL:

.PHONY=test
test: clean
	$(MAKE) egg_info
	tox

README: README.md
	echo -e '.. WARNING: AUTO-GENERATED FILE. DO NOT EDIT.\n' > $@
	pandoc --from=markdown --to=rst $< >> $@

.PHONY=clean
clean:
	rm -f src/jose/_jose*.s[ol] src/jose/_jose*.dyn
	rm -rf build dist
	find ./ -name '*.py[co]' -exec rm -f {} \;
	find ./ -depth -name __pycache__ -exec rm -rf {} \;

.PHONY=distclean
distclean: clean
	rm -f _jose.c
	rm -f MANIFEST
	rm -rf .tox .cache
	rm -rf src/*.egg-info *.egg-info

.PHONY=egg_info
egg_info: README
	$(PYTHON) setup.py egg_info

.PHONY=packages
packages: distclean egg_info
	$(PYTHON) setup.py packages

