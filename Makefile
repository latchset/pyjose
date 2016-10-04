PYTHON=python3

.NOTPARALLEL:

README: README.md
	echo -e '.. WARNING: AUTO-GENERATED FILE. DO NOT EDIT.\n' > $@
	pandoc --from=markdown --to=rst $< >> $@

.PHONY=clean
clean:
	rm -f jose/_jose*.s[ol] jose/_jose*.dyn
	rm -rf build dist
	find ./ -name '*.py[co]' -exec rm -f {} \;
	find ./ -depth -name __pycache__ -exec rm -rf {} \;

.PHONY=distclean
distclean: clean
	rm -f _jose.c
	rm -rf *.egg-info .tox MANIFEST .cache

.PHONY=egg_info
egg_info: README
	$(PYTHON) setup.py egg_info

.PHONY=packages
packages: clean egg_info
	$(PYTHON) setup.py packages

