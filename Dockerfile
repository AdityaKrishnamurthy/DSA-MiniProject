# Image for the whole pipeline (producer, processor, ML model, SQLite, dashboard).
# Built and started by:  docker compose up --build
FROM python:3.10-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Dataset and model are created inside the image, so the pickled model always matches
# the scikit-learn version installed above.
RUN python run.py train

EXPOSE 8501
CMD ["python", "run.py", "serve"]
