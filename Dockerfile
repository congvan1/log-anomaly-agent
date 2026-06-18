FROM python:3.12-slim

WORKDIR /app

# Core needs no deps; install optional ones so the LLM can be enabled with an API key.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY tests/ ./tests/

# Default: generate incident logs, detect, write reports to /app/sample_output.
ENTRYPOINT ["python", "-m", "src.pipeline"]
CMD ["--scenario", "incident", "--save-log", "sample_output/app_incident.log"]
