param(
    # Production Project ID: "vtrust-vn" (Dev Test Project: "second-core-501608-a5")
    [string]$ProjectId = "vtrust-vn",
    [string]$Region = "asia-southeast1"
)

$ErrorActionPreference = "Stop"

# Auto-detect gcloud SDK path and append to PATH if not present
$GCLOUD_PATH = "$env:LocalAppData\Google\Cloud SDK\google-cloud-sdk\bin"
if (Test-Path $GCLOUD_PATH) {
    if ($env:PATH -notlike "*$GCLOUD_PATH*") {
        $env:PATH = "$GCLOUD_PATH;$env:PATH"
    }
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "     VTRUST AI AGENT BACKEND DEPLOYMENT SCRIPT (FASTAPI)  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Configuration
$PROJECT_ID = $ProjectId
$REGION = $Region
$SERVICE_NAME = "vtrust-ai-agent"
$REPO_NAME = "vtrust-repo"

Write-Host "Preparing deployment for Project: $PROJECT_ID in Region: $REGION..." -ForegroundColor Yellow

# 2. Check gcloud authentication
try {
    Write-Host "Checking gcloud authentication..." -ForegroundColor DarkGray
    $activeAccount = gcloud auth list --filter="status:ACTIVE" --format="value(account)"
    if (-not $activeAccount) {
        Write-Host "ERROR: No active gcloud account found." -ForegroundColor Red
        Write-Host "Please run 'gcloud auth login' to authenticate first." -ForegroundColor Yellow
        exit
    }
    Write-Host "Active account: $activeAccount" -ForegroundColor Green
} catch {
    Write-Host "ERROR: gcloud CLI not found. Please install Google Cloud SDK." -ForegroundColor Red
    exit
}

# Set active project
gcloud config set project $PROJECT_ID

# 3. Create Artifact Registry repository if not exists
Write-Host "`n[Step 1/4] Checking Artifact Registry repository..." -ForegroundColor Yellow
$repoExists = gcloud artifacts repositories list --location=$REGION --filter="name:projects/$PROJECT_ID/locations/$REGION/repositories/$REPO_NAME" --format="value(name)"
if (-not $repoExists) {
    Write-Host "Creating Docker repository '$REPO_NAME' in $REGION..." -ForegroundColor Green
    gcloud artifacts repositories create $REPO_NAME --repository-format=docker --location=$REGION --description="VTrust Docker images repository" --project=$PROJECT_ID
} else {
    Write-Host "Repository '$REPO_NAME' already exists." -ForegroundColor Green
}

# 4. Build Container using Cloud Build
Write-Host "`n[Step 2/4] Building and pushing Docker image using Cloud Build..." -ForegroundColor Yellow
$IMAGE_TAG = "$REGION-docker.pkg.dev/$PROJECT_ID/$REPO_NAME/$SERVICE_NAME"
gcloud builds submit --tag $IMAGE_TAG --project=$PROJECT_ID

# 5. Deploy to Google Cloud Run
Write-Host "`n[Step 3/4] Deploying container to Google Cloud Run..." -ForegroundColor Yellow
gcloud run deploy $SERVICE_NAME --image $IMAGE_TAG --platform managed --region $REGION --memory 2Gi --cpu 2 --concurrency 10 --timeout 600 --min-instances 1 --max-instances 10 --allow-unauthenticated --set-env-vars="FIRESTORE_PROJECT_ID=$PROJECT_ID" --project=$PROJECT_ID

# Retrieve Cloud Run URL
$RUN_URL = gcloud run services describe $SERVICE_NAME --platform=managed --region=$REGION --format="value(status.url)"
Write-Host "`nCloud Run deployed successfully!" -ForegroundColor Green
Write-Host "Official API Endpoint: $RUN_URL" -ForegroundColor Cyan

# 6. Configure IAM permissions for Firestore
Write-Host "`n[Step 4/4] Configuring IAM permissions for Firestore..." -ForegroundColor Yellow
try {
    $PROJECT_NUMBER = gcloud projects describe $PROJECT_ID --format="value(projectNumber)"
    $SA_EMAIL = "$PROJECT_NUMBER-compute@developer.gserviceaccount.com"
    Write-Host "Cloud Run Service Account: $SA_EMAIL" -ForegroundColor DarkGray
    
    Write-Host "Granting Cloud Datastore User (Firestore read/write) role..." -ForegroundColor Green
    gcloud projects add-iam-policy-binding $PROJECT_ID --member="serviceAccount:$SA_EMAIL" --role="roles/datastore.user" --no-user-output-enabled
        
    Write-Host "Firestore IAM permissions configured successfully!" -ForegroundColor Green
} catch {
    Write-Host "Warning: Could not configure Firestore IAM automatically. Please manually grant 'Cloud Datastore User' role to your Cloud Run service account." -ForegroundColor Yellow
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "             DEPLOYMENT COMPLETE!                         " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "1. API Endpoint: $RUN_URL" -ForegroundColor White
Write-Host "2. Verify health at: $RUN_URL/health" -ForegroundColor White
Write-Host "3. Configure 'URL_AGENT_API_URL' in Next.js with this URL." -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Green
