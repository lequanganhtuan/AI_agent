import os
import pytest
from src.analyzers.url.ai_content_analysis.input.screenshot_encoder import encode_screenshot

def test_encode_screenshot_none_or_empty():
    assert encode_screenshot(None) is None
    assert encode_screenshot("") is None

def test_encode_screenshot_non_existent():
    assert encode_screenshot("non_existent_file.png") is None

def test_encode_screenshot_success(tmp_path):
    # Create a temporary mock image file
    mock_file = tmp_path / "mock_screenshot.png"
    binary_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01"
    mock_file.write_bytes(binary_data)
    
    # Run encoder
    result = encode_screenshot(str(mock_file))
    
    # Verify result is base64 encoded string of binary_data
    import base64
    expected = base64.b64encode(binary_data).decode("utf-8")
    assert result == expected

def test_encode_screenshot_read_failure(monkeypatch, tmp_path):
    mock_file = tmp_path / "mock_unreadable.png"
    mock_file.write_bytes(b"dummy content")
    
    # Mock open to raise PermissionError or similar
    def mock_open(*args, **kwargs):
        raise IOError("Mock I/O error")
        
    import builtins
    monkeypatch.setattr(builtins, "open", mock_open)
    
    result = encode_screenshot(str(mock_file))
    assert result is None
