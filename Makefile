.PHONY: help clean build publish_test publish_live

# https://packaging.python.org/tutorials/packaging-projects/
# https://realpython.com/pypi-publish-python-package/

help:
	@echo "Usage:"
	@echo "build        - build egg and wheel"
	@echo "clean        - clean artifacts"
	@echo "dist         - clean and then build artifacts"
	@echo "publish_test - publish to test PyPI"
	@echo "publish_live - publish to test PyPI"

build:
	python3 setup.py sdist bdist_wheel

clean:
	rm -rf dist *.egg-info

dist: clean build

publish_test:
	python3 -m twine upload --repository testpypi dist/*

publish_live:
	python3 -m twine upload --repository pypi dist/*
