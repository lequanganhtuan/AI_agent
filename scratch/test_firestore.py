import asyncio
import os
import sys
from dotenv import load_dotenv

# Add src to python path
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from src.core.database.firestore_repository import FirestoreRepository
from src.core.report.fraud_report import FraudReport
from src.core.models import ValidationResult, StaticAnalysisResult, ThreatIntelligenceResult, create_default_static_analysis, create_default_threat_intelligence
from datetime import datetime

async def test_write():
    # Load .env
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
    
    print("FIRESTORE_EMULATOR_HOST:", os.environ.get("FIRESTORE_EMULATOR_HOST"))
    print("FIRESTORE_PROJECT_ID:", os.environ.get("FIRESTORE_PROJECT_ID"))
    
    db = FirestoreRepository()
    print("Collection name:", db.collection_name)
    
    # Create a mock report
    report = FraudReport(
        id="test-uuid-12345",
        cache_key="test_cache_key",
        url="test-url.com",
        normalized_url="test-url.com",
        scanned_at=datetime.utcnow(),
        validation=ValidationResult(valid=True, normalized_url="test-url.com", cache_key="test_cache_key"),
        static=create_default_static_analysis("test-url.com"),
        threat_intel=create_default_threat_intelligence(),
        score=45,
        risk_level="medium",
        verdict="WARN"
    )
    
    try:
        doc_id = await db.save_report(report)
        print("Success! Document ID saved:", doc_id)
    except Exception as e:
        print("Error during save_report:", str(e))
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_write())
