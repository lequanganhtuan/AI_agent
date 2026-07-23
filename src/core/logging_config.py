import json
import logging
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Optional

# Global contextvar storing current request trace_id across coroutines
trace_id_var: ContextVar[Optional[str]] = ContextVar("trace_id", default=None)

def get_trace_id() -> Optional[str]:
    return trace_id_var.get()

def set_trace_id(trace_id: str) -> None:
    trace_id_var.set(trace_id)

class JSONFormatter(logging.Formatter):
    """Enterprise-grade Structured JSON Log Formatter with Trace ID injection."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "trace_id": get_trace_id() or getattr(record, "trace_id", None) or "N/A",
        }

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, ensure_ascii=False)
