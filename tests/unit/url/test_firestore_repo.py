import pytest
import os
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime

from src.core.database.firestore_repository import FirestoreRepository
from src.core.report.fraud_report import FraudReport
from src.core.settings import settings

VALID_REPORT_DICT = {
    "id": "f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
    "cache_key": "TEST_KEY",
    "url": "https://example.com",
    "normalized_url": "https://example.com",
    "scanned_at": "2026-07-06T09:28:16.123Z",
    "validation": {
        "valid": True,
        "normalized_url": "https://example.com",
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
    }
}

@pytest.fixture
def sample_report():
    return FraudReport.model_validate(VALID_REPORT_DICT)

def test_firestore_repository_initialization():
    with patch("src.core.database.firestore_repository.settings") as mock_settings:
        mock_settings.google_application_credentials = "mock_credentials.json"
        repo = FirestoreRepository(collection_name="test_collection")
        assert repo.collection_name == "test_collection"

@pytest.mark.anyio
async def test_save_report(sample_report):
    repo = FirestoreRepository(collection_name="test_scans")
    
    mock_client = MagicMock()
    mock_collection = MagicMock()
    mock_document = MagicMock()
    mock_set = AsyncMock()
    
    mock_client.collection.return_value = mock_collection
    mock_collection.document.return_value = mock_document
    mock_document.set = mock_set
    repo._client = mock_client
    
    # Save report
    doc_id = await repo.save_report(sample_report)
    
    # Must use report.id (UUID) instead of cache_key!
    assert doc_id == "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
    mock_client.collection.assert_called_once_with("test_scans")
    mock_collection.document.assert_called_once_with("f81d4fae-7dec-11d0-a765-00a0c91e6bf6")
    mock_set.assert_called_once()

@pytest.mark.anyio
async def test_get_report_by_id(sample_report):
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
    
    # Document missing
    mock_doc_snapshot.exists = False
    res = await repo.get_report_by_id("nonexistent")
    assert res is None
    
    # Document present
    mock_doc_snapshot.exists = True
    mock_doc_snapshot.to_dict.return_value = VALID_REPORT_DICT
    
    res = await repo.get_report_by_id("f81d4fae-7dec-11d0-a765-00a0c91e6bf6")
    assert res is not None
    assert isinstance(res, FraudReport)
    assert res.id == "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
