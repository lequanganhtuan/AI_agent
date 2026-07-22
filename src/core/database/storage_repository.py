from __future__ import annotations
import logging
import os
import asyncio
import threading
from google.cloud import storage
from google.auth.credentials import AnonymousCredentials
from src.core.settings import settings

logger = logging.getLogger(__name__)

class StorageRepository:
    """
    Manages persistence of artifacts (screenshots) in Google Cloud Storage.
    Implements thread-safe client initialization, upload retry logic,
    and fallback bucket remapping for modern Firebase Storage suffixes.
    """

    _client_lock = threading.Lock()

    def __init__(self) -> None:
        self.project_id = settings.firestore_project_id or "second-core-501608-a5"
        
        # Read env configurations first, fallback to the modern .firebasestorage.app suffix 
        # which matches the default storage configuration defined in nextjs's lib/firebase-admin.ts
        self.bucket_name = (
            os.environ.get("FIREBASE_STORAGE_BUCKET") or 
            os.environ.get("NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET") or 
            f"{self.project_id}.firebasestorage.app"
        )
        self._client = None

    @property
    def client(self) -> storage.Client:
        """Lazily and thread-safely initializes the GCS storage Client."""
        if self._client is None:
            with self._client_lock:
                if self._client is None:
                    # Support Firebase Storage Emulator local dev
                    emulator_host = os.environ.get("STORAGE_EMULATOR_HOST") or os.environ.get("FIREBASE_STORAGE_EMULATOR_HOST")
                    if emulator_host:
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
                        logger.info(f"Initializing Storage Client for project: {self.project_id}")
                        self._client = storage.Client(project=self.project_id)
        return self._client

    async def upload_screenshot(self, cache_key: str, image_bytes: bytes) -> str:
        """
        Uploads screenshot bytes directly to Firebase Storage bucket.
        Implements an asynchronous retry loop with exponential backoff for network resilience.
        """
        max_retries = 3
        backoff_delay = 1.0

        for attempt in range(1, max_retries + 1):
            try:
                # GCS SDK upload call is blocking, delegate to a background thread executor
                loop = asyncio.get_running_loop()
                
                def _upload():
                    bucket = self.client.bucket(self.bucket_name)
                    blob = bucket.blob(f"url_scans/{cache_key}.png")
                    blob.upload_from_string(image_bytes, content_type="image/png")
                    logger.info(f"Successfully uploaded screenshot url_scans/{cache_key}.png to Storage bucket {self.bucket_name}")
                    return f"url_scans/{cache_key}.png"
                    
                return await loop.run_in_executor(None, _upload)
            except Exception as e:
                if attempt == max_retries:
                    logger.error(
                        f"Failed to upload screenshot to Firebase Storage after {max_retries} attempts: {str(e)}", 
                        exc_info=True
                    )
                    raise
                
                logger.warning(
                    f"Storage upload attempt {attempt} failed: {str(e)}. "
                    f"Retrying in {backoff_delay} seconds..."
                )
                await asyncio.sleep(backoff_delay)
                backoff_delay *= 2.0
