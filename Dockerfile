# Playwright's official image already ships Chromium + all system libs,
# which keeps the Render build simple and reliable.
FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Render injects $PORT at runtime. One worker so there is a single bot/browser.
ENV PORT=10000
EXPOSE 10000

CMD gunicorn -w 1 --threads 8 --timeout 60 -b 0.0.0.0:$PORT app:app
