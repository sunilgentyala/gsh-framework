FROM python:3.12-slim
WORKDIR /gsh
COPY requirements.txt ./
# The demo needs only PyYAML; the rest of requirements.txt is optional.
RUN pip install --no-cache-dir "pyyaml>=6.0.1"
COPY adapters ./adapters
COPY scripts ./scripts
COPY configs ./configs
COPY demo ./demo
ENV PYTHONUNBUFFERED=1
CMD ["python", "demo/run_demo.py"]
