import logging
from src.core.enums import ValidationErrorCode

logger = logging.getLogger(__name__)

class URLValidationException(Exception):
    def __init__(self, code: ValidationErrorCode, message: str):
        self.code = code
        self.message = message
        super().__init__(message)
        
        logger.warning(f"[URL_VALIDATION_FAILED] Code: {code.value} | Message: {message}")