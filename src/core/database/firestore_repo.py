import os
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from google.cloud.firestore import AsyncClient, Query

from src.core.settings import settings
from src.core.models import AnalysisContext

logger = logging.getLogger(__name__)

# Ensure Google Application Credentials environment variable is set
if settings.google_application_credentials:
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = settings.google_application_credentials

class FirestoreRepository:
    """Manages persistence of URL Analysis Scans in Google Cloud Firestore."""

    def __init__(self, collection_name: str = "scans") -> None:
        self.collection_name = collection_name
        self._client: Optional[AsyncClient] = None

    @property
    def client(self) -> AsyncClient:
        """Lazily initializes the Firestore AsyncClient."""
        if self._client is None:
            project = settings.firestore_project_id
            logger.info(f"Initializing Firestore AsyncClient for project: {project}")
            self._client = AsyncClient(project=project)
        return self._client

    async def save_scan(self, context: AnalysisContext) -> str:
        """Serializes and saves a complete URL scan context in Firestore.

        Returns:
            The document ID of the saved scan.
        """
        # Convert to dictionary representation (preserving raw structures)
        data = context.model_dump(by_alias=True)
        
        # Add a top-level timestamp for sorting historical scans
        data["scanned_at"] = datetime.utcnow()
        
        # We can use the cache_key or validation.cache_key if present, or generate one
        doc_id = None
        if context.validation and context.validation.cache_key:
            doc_id = context.validation.cache_key
        
        if doc_id:
            doc_ref = self.client.collection(self.collection_name).document(doc_id)
            await doc_ref.set(data)
            logger.info(f"Successfully saved scan to Firestore with ID: {doc_id}")
            return doc_id
        else:
            # Fallback to auto-generated ID
            doc_ref = self.client.collection(self.collection_name).document()
            await doc_ref.set(data)
            logger.info(f"Successfully saved scan to Firestore with auto-generated ID: {doc_ref.id}")
            return doc_ref.id

    async def get_recent_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Queries Firestore for the most recent scan records.

        Returns:
            A list of lightweight scan summaries suitable for UI history drawers.
        """
        try:
            query = (
                self.client.collection(self.collection_name)
                .order_by("scanned_at", direction=Query.DESCENDING)
                .limit(limit)
            )
            
            docs = await query.get()
            summaries = []
            
            for doc in docs:
                doc_data = doc.to_dict()
                if not doc_data:
                    continue
                
                # Extract clean flat summary details to keep UI payload small
                validation = doc_data.get("validation", {})
                url = validation.get("normalized_url") or doc_data.get("url") or ""
                
                # Risk info extraction
                score = 0
                level = "LOW"
                verdict = "ALLOW"
                
                ai = doc_data.get("ai")
                if ai:
                    ai_risk = ai.get("risk")
                    if ai_risk:
                        score = ai_risk.get("score", 0)
                        level = ai_risk.get("level", "LOW")
                    
                    ai_content = ai.get("content")
                    if ai_content:
                        verdict = ai_content.get("recommended_action", "ALLOW")
                else:
                    # Fallback to threat intelligence
                    threat = doc_data.get("threat_intel")
                    if threat:
                        threat_risk = threat.get("risk")
                        if threat_risk:
                            score = threat_risk.get("score", 0)
                            level = threat_risk.get("risk_level", "LOW")
                            if score >= 50:
                                verdict = "BLOCK"
                            elif score >= 20:
                                verdict = "WARN"
                
                scanned_at = doc_data.get("scanned_at")
                if isinstance(scanned_at, datetime):
                    formatted_time = scanned_at.isoformat()
                else:
                    formatted_time = str(scanned_at)

                summaries.append({
                    "id": doc.id,
                    "url": url,
                    "score": score,
                    "level": level,
                    "verdict": verdict,
                    "timestamp": formatted_time
                })
            
            return summaries
        except Exception as e:
            logger.error(f"Failed to query recent scans from Firestore: {str(e)}", exc_info=True)
            return []

    async def get_scan_by_id(self, scan_id: str) -> Optional[AnalysisContext]:
        """Retrieves and deserializes a complete AnalysisContext by its document ID."""
        try:
            doc_ref = self.client.collection(self.collection_name).document(scan_id)
            doc = await doc_ref.get()
            
            if not doc.exists:
                logger.warning(f"Scan document not found: {scan_id}")
                return None
                
            doc_data = doc.to_dict()
            if not doc_data:
                return None

            # Remove scanned_at helper metadata before validating into model
            doc_data.pop("scanned_at", None)
            
            # Use model_validate to deserialize dict back into Pydantic models
            return AnalysisContext.model_validate(doc_data)
        except Exception as e:
            logger.error(f"Failed to retrieve scan {scan_id} from Firestore: {str(e)}", exc_info=True)
            return None
