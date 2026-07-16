import logging
import threading
from typing import List, Dict, Any, Optional
from datetime import datetime
from google.cloud.firestore import AsyncClient, Query

from src.core.settings import settings
from src.core.database.base_repository import BaseRepository
from src.core.report.fraud_report import FraudReport

logger = logging.getLogger(__name__)

class FirestoreRepository(BaseRepository):
    """Manages persistence of FraudReports in Google Cloud Firestore."""

    _client_lock = threading.Lock()

    def __init__(self, collection_name: Optional[str] = None) -> None:
        self.collection_name = collection_name or settings.firestore_collection_name
        self._client: Optional[AsyncClient] = None

    @property
    def client(self) -> AsyncClient:
        """Lazily and thread-safely initializes the Firestore AsyncClient."""
        if self._client is None:
            with self._client_lock:
                if self._client is None:
                    project = settings.firestore_project_id
                    database = settings.firestore_database_id
                    logger.info(f"Initializing Firestore AsyncClient for project: {project}, database: {database}")
                    self._client = AsyncClient(project=project, database=database)
        return self._client

    async def save_report(self, report: FraudReport) -> str:
        """Serializes and saves a FraudReport in Firestore.
        
        Uses report.id (UUID) as the Document ID to ensure all historical rescans are preserved.
        """
        try:
            # Convert to dictionary representation preserving Pydantic serializations
            data = report.model_dump(by_alias=True)
            doc_id = report.id
            
            doc_ref = self.client.collection(self.collection_name).document(doc_id)
            await doc_ref.set(data)
            logger.info(f"Successfully saved FraudReport to Firestore with ID: {doc_id}")
            return doc_id
        except Exception as e:
            logger.error(f"Failed to save FraudReport to Firestore: {str(e)}", exc_info=True)
            raise

    async def get_recent_reports(
        self,
        limit: int = 20,
        search: Optional[str] = None,
        verdict: Optional[str] = None,
        risk: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Queries Firestore for recent scan records matching criteria.
        
        Applies server-side filtering logic for risk, verdict, and limit (when local search is not set).
        """
        try:
            query = self.client.collection(self.collection_name)
            
            # Apply server-side filters if provided
            if verdict:
                query = query.where("ai.content.recommended_action", "==", verdict.upper())
                
            if risk:
                query = query.where("ai.risk.level", "==", risk.upper())
            
            # Order by timestamp descending
            query = query.order_by("scanned_at", direction=Query.DESCENDING)
            
            # Critical Performance Improvement: Apply limit directly on database queries when local search filter is not used
            if not search:
                query = query.limit(limit)
            
            docs = await query.get()
            summaries = []
            
            for doc in docs:
                doc_data = doc.to_dict()
                if not doc_data:
                    continue
                
                url = doc_data.get("url") or ""
                
                # Perform search substring filter locally if query is provided
                if search and search.lower() not in url.lower():
                    continue
                
                # Delegate to decoupled mapper function
                summary = self._build_summary(doc.id, doc_data)
                summaries.append(summary)
                
                if len(summaries) >= limit:
                    break
            
            return summaries
        except Exception as e:
            logger.error(f"Failed to query recent reports from Firestore: {str(e)}", exc_info=True)
            raise

    async def get_report_by_id(self, report_id: str) -> Optional[FraudReport]:
        """Retrieves and deserializes a complete FraudReport by its document ID (UUID)."""
        try:
            doc_ref = self.client.collection(self.collection_name).document(report_id)
            doc = await doc_ref.get()
            
            if not doc.exists:
                logger.warning(f"FraudReport document not found: {report_id}")
                return None
                
            doc_data = doc.to_dict()
            if not doc_data:
                return None
            
            return FraudReport.model_validate(doc_data)
        except Exception as e:
            logger.error(f"Failed to retrieve report {report_id} from Firestore: {str(e)}", exc_info=True)
            raise

    def _build_summary(self, doc_id: str, doc_data: Dict[str, Any]) -> Dict[str, Any]:
        """Helper to build a summary map for history list views."""
        url = doc_data.get("url") or ""
        score = 0.0
        risk_level = "LOW"
        verdict_val = "ALLOW"
        
        ai = doc_data.get("ai")
        if ai:
            ai_risk = ai.get("risk")
            if ai_risk:
                score = ai_risk.get("score", 0.0)
                risk_level = ai_risk.get("level", "LOW")
            
            ai_content = ai.get("content")
            if ai_content:
                verdict_val = ai_content.get("recommended_action", "ALLOW")
        
        scanned_at = doc_data.get("scanned_at")
        if isinstance(scanned_at, datetime):
            formatted_time = scanned_at.isoformat()
        else:
            formatted_time = str(scanned_at)

        return {
            "id": doc_id,
            "url": url,
            "score": score,
            "level": risk_level,
            "verdict": verdict_val,
            "timestamp": formatted_time
        }
