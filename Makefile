clean:
	rm -f -r build/
	rm -f -r dist/
	rm -f -r *.egg-info
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f  {} +

publish: clean
	python3 setup.py sdist bdist_wheel
	python3 -m twine upload dist/*

rebuild: clean
	python3 setup.py install

build:
	python3 setup.py install