from __future__ import annotations
import logging
import os
import asyncio
import threading
import random
from google.cloud import storage
from google.auth.credentials import AnonymousCredentials
from google.api_core.exceptions import (
    Forbidden,
    Unauthorized,
    InvalidArgument,
    NotFound,
)
from src.core.settings import settings

logger = logging.getLogger(__name__)

# Exceptions that should fail fast immediately without wasteful retry delays
NON_RETRIABLE_EXCEPTIONS = (Forbidden, Unauthorized, InvalidArgument, NotFound)


class StorageRepository:
    """
    Manages persistence of artifacts (screenshots) in Google Cloud Storage.
    Implements thread-safe client initialization, optimized bucket resolution,
    and resilient exponential backoff with jitter for transient errors.
    """

    _client_lock = threading.Lock()

    def __init__(self) -> None:
        # Default Production Project ID: 'vtrust-vn' (Personal Test Project ID: 'second-core-501608-a5')
        self.project_id = settings.firestore_project_id or "vtrust-vn" # or "second-core-501608-a5"
        
        # Read env configurations first, fallback to the modern .firebasestorage.app suffix 
        # which matches the default storage configuration defined in nextjs's lib/firebase-admin.ts
        self.bucket_name = (
            os.environ.get("FIREBASE_STORAGE_BUCKET") or 
            os.environ.get("NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET") or 
            f"{self.project_id}.firebasestorage.app"
        )
        self._client: storage.Client | None = None
        self._bucket_verified: bool = False
        self._is_emulator: bool = False

    @property
    def client(self) -> storage.Client:
        """Lazily and thread-safely initializes the GCS storage Client."""
        if self._client is None:
            with self._client_lock:
                if self._client is None:
                    # Support Firebase Storage Emulator local dev
                    emulator_host = os.environ.get("STORAGE_EMULATOR_HOST") or os.environ.get("FIREBASE_STORAGE_EMULATOR_HOST")
                    if emulator_host:
                        self._is_emulator = True
                        logger.info(f"Initializing Storage Client for EMULATOR. Project: {self.project_id}")
                        # Normalize emulator protocol safely inside initialization lock
                        if not emulator_host.startswith("http"):
                            os.environ["STORAGE_EMULATOR_HOST"] = f"http://{emulator_host}"
                        else:
                            os.environ["STORAGE_EMULATOR_HOST"] = emulator_host
                        
                        self._client = storage.Client(
                            project=self.project_id,
                            credentials=AnonymousCredentials()
                        )
                    else:
                        self._is_emulator = False
                        logger.info(f"Initializing Storage Client for project: {self.project_id}")
                        self._client = storage.Client(project=self.project_id)
        return self._client

    def _get_bucket(self) -> storage.Bucket:
        """Gets bucket reference with one-time verification for emulator mode."""
        bucket = self.client.bucket(self.bucket_name)
        if not self._bucket_verified:
            if self._is_emulator:
                try:
                    if not bucket.exists():
                        logger.info(f"Bucket {self.bucket_name} does not exist on emulator. Auto-creating...")
                        bucket = self.client.create_bucket(self.bucket_name)
                except Exception:
                    try:
                        bucket = self.client.create_bucket(self.bucket_name)
                    except Exception:
                        pass
            self._bucket_verified = True
        return bucket

    async def upload_screenshot(self, cache_key: str, image_bytes: bytes) -> str:
        """
        Uploads screenshot bytes directly to Firebase Storage bucket.
        Implements intelligent retry logic with backoff + jitter for transient network failures.
        """
        max_retries = 3
        backoff_delay = 1.0
        loop = asyncio.get_running_loop()

        for attempt in range(1, max_retries + 1):
            try:
                def _upload() -> str:
                    bucket = self._get_bucket()
                    blob = bucket.blob(f"url_scans/{cache_key}.png")
                    blob.upload_from_string(image_bytes, content_type="image/png")
                    logger.info(f"Successfully uploaded screenshot url_scans/{cache_key}.png to Storage bucket {self.bucket_name}")
                    return f"url_scans/{cache_key}.png"
                    
                return await loop.run_in_executor(None, _upload)
            except Exception as e:
                # Fail fast on non-retriable client/credential/permission errors (4xx)
                if isinstance(e, NON_RETRIABLE_EXCEPTIONS):
                    logger.error(f"Non-retriable error encountered during Storage upload ({type(e).__name__}): {str(e)}")
                    raise

                if attempt == max_retries:
                    logger.error(
                        f"Failed to upload screenshot to Firebase Storage after {max_retries} attempts: {str(e)}", 
                        exc_info=True
                    )
                    raise
                
                # Add randomized jitter (0 to 0.5s) to prevent thundering herd
                jitter = random.uniform(0.0, 0.5)
                sleep_time = backoff_delay + jitter
                logger.warning(
                    f"Storage upload attempt {attempt} failed ({type(e).__name__}: {str(e)}). "
                    f"Retrying in {sleep_time:.2f} seconds..."
                )
                await asyncio.sleep(sleep_time)
                backoff_delay *= 2.0
