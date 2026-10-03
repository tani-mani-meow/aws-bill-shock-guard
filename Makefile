.PHONY: install lint test cov tf-check package deploy destroy

install:
	python -m pip install -e .[dev]

lint:
	ruff check .
	ruff format --check .
	mypy src

test:
	pytest -q

cov:
	pytest -q --cov=bill_shock_guard --cov-report=term-missing

tf-check:
	terraform fmt -check -recursive terraform
	terraform -chdir=terraform/modules/guard init -backend=false
	terraform -chdir=terraform/modules/guard validate
	terraform -chdir=terraform/examples/basic init -backend=false
	terraform -chdir=terraform/examples/basic validate
	terraform -chdir=terraform/examples/test-fixtures init -backend=false
	terraform -chdir=terraform/examples/test-fixtures validate

package:
	python -c "import shutil, pathlib; p = pathlib.Path('build/lambda'); shutil.rmtree(p, ignore_errors=True); p.mkdir(parents=True, exist_ok=True); shutil.copytree('src/bill_shock_guard', p / 'bill_shock_guard')"

deploy:
	@echo "Deploying via terraform/examples/basic..."
	terraform -chdir=terraform/examples/basic init
	terraform -chdir=terraform/examples/basic apply

destroy:
	@echo "Destroying via terraform/examples/basic..."
	terraform -chdir=terraform/examples/basic destroy
