.PHONY: init
init: init-ci
	pip install pre-commit
	pre-commit install

.PHONY: init-ci
init-ci:
	pip install -r requirements.txt
	pip install -r requirements_test.txt

.PHONY: lint
lint:
	ruff check src tests

.PHONY: format
format:
	ruff format --check src tests

.PHONY: lint-fix
lint-fix:
	ruff check --fix src tests
	ruff format src tests

.PHONY: test
test:
	coverage run -m pytest tests
	coverage report
