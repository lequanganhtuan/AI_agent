param(
    [string]$ProjectId = "second-core-501608-a5",
    [string]$Region = "asia-southeast1"
)

$ErrorActionPreference = "Stop"

# Tự động thêm đường dẫn Google Cloud SDK vào PATH nếu chưa có
$GCLOUD_PATH = "$env:LocalAppData\Google\Cloud SDK\google-cloud-sdk\bin"
if (Test-Path $GCLOUD_PATH) {
    if ($env:PATH -notlike "*$GCLOUD_PATH*") {
        $env:PATH = "$GCLOUD_PATH;$env:PATH"
    }
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  HỆ THỐNG TRIỂN KHAI TỰ ĐỘNG VTRUST AI AGENT (FASTAPI)  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Thu thập thông tin dự án GCP
$PROJECT_ID = $ProjectId
$REGION = $Region

$SERVICE_NAME = "vtrust-ai-agent"
$REPO_NAME = "vtrust-repo"

Write-Host "`nĐang chuẩn bị triển khai lên Project: $PROJECT_ID tại Region: $REGION..." -ForegroundColor Yellow

# 2. Kiểm tra xác thực gcloud
try {
    Write-Host "Kiểm tra trạng thái đăng nhập gcloud..." -ForegroundColor DarkGray
    $activeAccount = gcloud auth list --filter="status:ACTIVE" --format="value(account)"
    if (-not $activeAccount) {
        Write-Host "LỖI: Bạn chưa đăng nhập tài khoản Google Cloud CLI." -ForegroundColor Red
        Write-Host "Vui lòng chạy lệnh 'gcloud auth login' để đăng nhập trước khi chạy script này." -ForegroundColor Yellow
        exit
    }
    Write-Host "Tài khoản active: $activeAccount" -ForegroundColor Green
} catch {
    Write-Host "LỖI: Không tìm thấy gcloud CLI. Vui lòng cài đặt Google Cloud SDK trước." -ForegroundColor Red
    exit
}

# Cấu hình project active
gcloud config set project $PROJECT_ID

# 3. Tạo Artifact Registry repository nếu chưa tồn tại
Write-Host "`n[Bước 1/4] Kiểm tra kho lưu trữ Artifact Registry..." -ForegroundColor Yellow
$repoExists = gcloud artifacts repositories list --location=$REGION --filter="name:projects/$PROJECT_ID/locations/$REGION/repositories/$REPO_NAME" --format="value(name)"
if (-not $repoExists) {
    Write-Host "Đang tạo kho lưu trữ Docker '$REPO_NAME' tại $REGION..." -ForegroundColor Green
    gcloud artifacts repositories create $REPO_NAME `
        --repository-format=docker `
        --location=$REGION `
        --description="VTrust Docker images repository" `
        --project=$PROJECT_ID
} else {
    Write-Host "Kho lưu trữ '$REPO_NAME' đã tồn tại." -ForegroundColor Green
}

# 4. Đóng gói Container bằng Cloud Build
Write-Host "`n[Bước 2/4] Đóng gói và đẩy Container Image lên đám mây (Cloud Build)..." -ForegroundColor Yellow
$IMAGE_TAG = "$REGION-docker.pkg.dev/$PROJECT_ID/$REPO_NAME/$SERVICE_NAME"
gcloud builds submit --tag $IMAGE_TAG --project=$PROJECT_ID

# 5. Deploy lên Google Cloud Run
Write-Host "`n[Bước 3/4] Triển khai Container lên Google Cloud Run..." -ForegroundColor Yellow
gcloud run deploy $SERVICE_NAME `
    --image $IMAGE_TAG `
    --platform managed `
    --region $REGION `
    --memory 2Gi `
    --cpu 2 `
    --concurrency 10 `
    --timeout 600 `
    --min-instances 1 `
    --max-instances 10 `
    --allow-unauthenticated `
    --set-env-vars="FIRESTORE_PROJECT_ID=$PROJECT_ID" `
    --project=$PROJECT_ID

# Lấy URL của Cloud Run
$RUN_URL = gcloud run services describe $SERVICE_NAME --platform=managed --region=$REGION --format="value(status.url)"
Write-Host "`nTriển khai Cloud Run thành công!" -ForegroundColor Green
Write-Host "Đường dẫn API chính thức: $RUN_URL" -ForegroundColor Cyan

# 6. Tự động phân quyền IAM cho Firestore
Write-Host "`n[Bước 4/4] Cấu hình phân quyền IAM cho Firestore Database..." -ForegroundColor Yellow
try {
    $PROJECT_NUMBER = gcloud projects describe $PROJECT_ID --format="value(projectNumber)"
    $SA_EMAIL = "$PROJECT_NUMBER-compute@developer.gserviceaccount.com"
    Write-Host "Tài khoản Service Account của Cloud Run: $SA_EMAIL" -ForegroundColor DarkGray
    
    Write-Host "Đang gán vai trò Cloud Datastore User (đọc/ghi Firestore)..." -ForegroundColor Green
    gcloud projects add-iam-policy-binding $PROJECT_ID `
        --member="serviceAccount:$SA_EMAIL" `
        --role="roles/datastore.user" `
        --no-user-output-enabled
        
    Write-Host "Gán quyền Firestore IAM thành công!" -ForegroundColor Green
} catch {
    Write-Host "Cảnh báo: Không thể tự động gán quyền IAM Firestore. Vui lòng cấp quyền thủ công vai trò 'Cloud Datastore User' cho tài khoản dịch vụ mặc định của Cloud Run." -ForegroundColor Yellow
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "             QUÁ TRÌNH TRIỂN KHAI HOÀN TẤT!               " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "1. API Endpoint của bạn: $RUN_URL" -ForegroundColor White
Write-Host "2. Hãy kiểm tra trạng thái sức khỏe tại: $RUN_URL/health" -ForegroundColor White
Write-Host "3. Cấu hình biến môi trường 'URL_AGENT_API_URL' trong Next.js trỏ về link trên." -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Green
