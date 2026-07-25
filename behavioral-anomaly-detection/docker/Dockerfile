# Scaffold — extend once src/pipeline/{train,infer}.py are implemented.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Regenerate synthetic data at build time (or mount data/ as a volume instead)
RUN python -m src.data_generation.generate_dataset

# Default: launch the analyst dashboard
EXPOSE 8501
CMD ["streamlit", "run", "dashboard/app.py", "--server.address=0.0.0.0"]
