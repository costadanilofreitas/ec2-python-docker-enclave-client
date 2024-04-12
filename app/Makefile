.PHONY: help clean clean-build coverage

.DEFAULT: help

help:
	@echo "make clean"
	@echo "        prepare development environment, use only once"
	@echo "make clean-build"
	@echo "        Clear all build directories"
	@echo "make coverage"
	@echo "        run coverage command cli in development features"
	@echo "make lint"
	@echo "        run lint"
	@echo "make test"
	@echo "        run tests"

clean:
	find . -name '*.pyc' -exec rm --force {} +
	find . -name '*.pyo' -exec rm --force {} +
	find . | grep -E "__pycache__|.pyc" | xargs rm -rf

clean-build:
	rm --force --recursive build/
	rm --force --recursive dist/
	rm --force --recursive *.egg-info

coverage: 		 
	python3.7 -m pytest --cov-report xml --cov=./

test: 
	python3.7 -m pytest --verbose --color=yes
#test:
#    @echo "test"

lint:
	flake8 --ignore E305 --max-line-length=130 --exclude .git,__pycache__
	bandit -r -111 .
#lint:
#    @echo "lint"
