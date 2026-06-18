.PHONY: help setup demo normal test report clean docker-build docker-run

PY ?= python3

help:           ## Show available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n",$$1,$$2}'

setup:          ## Create venv + install optional deps
	$(PY) -m venv .venv && .venv/bin/pip install -q -r requirements.txt

demo:           ## Run full pipeline in INCIDENT mode (default)
	$(PY) -m src.pipeline --scenario incident --save-log sample_output/app_incident.log

normal:         ## Run pipeline in NORMAL mode (expect: no P1)
	$(PY) -m src.pipeline --scenario normal --save-log sample_output/app_normal.log \
		--html sample_output/report_normal.html --json sample_output/report_normal.json

test:           ## Run the automated test suite
	$(PY) -m pytest -q

report:         ## Open the latest HTML report (macOS)
	open sample_output/report.html

clean:          ## Remove generated output
	rm -f sample_output/*.log sample_output/report*.html sample_output/report*.json

docker-build:   ## Build the image
	docker build -t log-anomaly-agent .

docker-run:     ## Run the demo in a container, writing reports to ./sample_output
	docker run --rm -e ANTHROPIC_API_KEY=$$ANTHROPIC_API_KEY \
		-v $$(pwd)/sample_output:/app/sample_output log-anomaly-agent
