# Use official Python runtime as base image
FROM python:3.11-slim-bookworm

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PORT=8000

# Set working directory
WORKDIR /app

# Install system dependencies needed for Playwright and browser execution
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright Chromium and its system dependencies
RUN playwright install --with-deps chromium

# Copy application source code
COPY src/ ./src/

# Expose port
EXPOSE 8000

# Command to run FastAPI app using uvicorn
CMD uvicorn src.app:app --host 0.0.0.0 --port $PORT
