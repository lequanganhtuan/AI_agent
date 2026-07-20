# Sử dụng Python 3.12 slim làm base image
FROM python:3.12-slim

# Cài đặt các thư viện hệ thống cơ bản
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Thiết lập thư mục làm việc
WORKDIR /app

# Sao chép file requirements và cài đặt thư viện Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Cài đặt trình duyệt Playwright Chromium và tự động cài đặt mọi dependencies hệ thống cần thiết
RUN playwright install chromium
RUN playwright install-deps chromium

# Sao chép toàn bộ mã nguồn của AI Agent vào container
COPY . .

# Cấu hình cổng chạy mặc định
EXPOSE 8000

# Cấu hình các biến môi trường chạy production
ENV PORT=8000
ENV HOST=0.0.0.0

# Khởi chạy FastAPI sử dụng Uvicorn
CMD ["uvicorn", "src.app:app", "--host", "0.0.0.0", "--port", "8000"]
