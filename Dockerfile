FROM python:3.12-slim

# ping is needed for the command-injection challenge
RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home player

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p /app/data && chown -R player:player /app

USER player
ENV LAB_HOST=0.0.0.0 LAB_PORT=5000 PYTHONUNBUFFERED=1
EXPOSE 5000
CMD ["python", "app.py"]
