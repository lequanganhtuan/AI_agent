from __future__ import annotations

class DynamicAnalysisError(Exception):
    """Base exception for all dynamic analysis operations."""
    pass

class NavigationError(DynamicAnalysisError):
    """Raised when navigation to a URL fails due to DNS issues, timeouts, SSL errors, or connection resets."""
    pass

class ScreenshotCaptureError(DynamicAnalysisError):
    """Raised when capturing a screenshot of the loaded page fails."""
    pass
