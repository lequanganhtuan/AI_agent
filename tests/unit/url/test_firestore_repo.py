import pytest
import os
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime

from src.core.database.firestore_repo import FirestoreRepository
from src.core.models import AnalysisContext, ValidationResult, StaticAnalysisResult, ThreatIntelligenceResult
from src.core.settings import settings

@pytest.fixture
def mock_context():
    validation = ValidationResult.model_construct(valid=True, normalized_url="https://test.com", cache_key="TEST_KEY")
    static = StaticAnalysisResult.model_construct()
    threat_intel = ThreatIntelligenceResult.model_construct()
    
    return AnalysisContext.model_construct(
        validation=validation,
        static=static,
        threat_intel=threat_intel
    )

def test_firestore_repository_initialization():
    with patch("src.core.database.firestore_repo.settings") as mock_settings:
        mock_settings.google_application_credentials = "mock_credentials.json"
        repo = FirestoreRepository(collection_name="test_collection")
        assert repo.collection_name == "test_collection"

@pytest.mark.anyio
async def test_save_scan(mock_context):
    repo = FirestoreRepository(collection_name="test_scans")
    
    # Mock firestore client methods
    mock_client = MagicMock()
    mock_collection = MagicMock()
    mock_document = MagicMock()
    mock_set = AsyncMock()
    
    mock_client.collection.return_value = mock_collection
    mock_collection.document.return_value = mock_document
    mock_document.set = mock_set
    repo._client = mock_client
    
    # Save scan
    doc_id = await repo.save_scan(mock_context)
    
    assert doc_id == "TEST_KEY"
    mock_client.collection.assert_called_once_with("test_scans")
    mock_collection.document.assert_called_once_with("TEST_KEY")
    mock_set.assert_called_once()
    
    # Check that scanned_at timestamp was added to the payload
    called_payload = mock_set.call_args[0][0]
    assert "scanned_at" in called_payload
    assert isinstance(called_payload["scanned_at"], datetime)

@pytest.mark.anyio
async def test_get_scan_by_id(mock_context):
    repo = FirestoreRepository(collection_name="test_scans")
    
    mock_client = MagicMock()
    mock_collection = MagicMock()
    mock_document = MagicMock()
    mock_get = AsyncMock()
    mock_doc_snapshot = MagicMock()
    
    mock_client.collection.return_value = mock_collection
    mock_collection.document.return_value = mock_document
    mock_document.get = mock_get
    mock_get.return_value = mock_doc_snapshot
    repo._client = mock_client
    
    # Test document missing
    mock_doc_snapshot.exists = False
    res = await repo.get_scan_by_id("nonexistent")
    assert res is None
    
    # Test document present
    mock_doc_snapshot.exists = True
    # Setup Pydantic mock representation
    mock_doc_snapshot.to_dict.return_value = {
        "validation": {
            "valid": True,
            "normalized_url": "https://test.com",
            "cache_key": "TEST_KEY"
        },
        "static": {
            "lexical": {
                "url_length": 16,
                "root_domain_length": 8,
                "full_domain_length": 8,
                "subdomain_count": 0,
                "url_special_char_count": 0,
                "digit_ratio_domain": 0.0,
                "domain_entropy": 2.5,
                "hyphen_count": 0,
                "url_depth": 0,
                "query_parameter_count": 0,
                "max_path_segment_length": 0,
                "longest_token_length": 0,
                "consecutive_digit_count": 0
            },
            "brand": {},
            "pattern": {},
            "tld": {},
            "typosquatting": {},
            "risk": {
                "score": 0,
                "risk_level": "low"
            }
        },
        "threat_intel": {
            "virustotal": {},
            "google_safe_browsing": {},
            "urlscan": {},
            "ip_reputation": {},
            "risk": {
                "score": 0,
                "risk_level": "low"
            }
        },
        "scanned_at": datetime.utcnow()
    }
    
    res = await repo.get_scan_by_id("TEST_KEY")
    assert res is not None
    assert isinstance(res, AnalysisContext)
    assert res.validation.normalized_url == "https://test.com"
