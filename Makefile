all:
	@echo "make release			- Upload to pypi"

NAME:=$(shell python3 setup.py --name)
VERSION:=$(shell python3 setup.py --version | sed 's/+/-/g')

clean:
	rm -fr dist

bump: clean
	python3 bump.py jwt_rsa/version.py

sdist: bump
	python3 setup.py sdist bdist_wheel

upload: sdist
	twine upload dist/*

test:
	tox

purge: clean
	rm -fr env *.egg-info .tox dist

develop: purge bump
	virtualenv -p python3.6 env
	env/bin/pip install certifi
	env/bin/pip install -Ue '.'
	env/bin/pip install -Ue '.[develop]'
