from __future__ import annotations

from src.analyzers.url.dynamic_analysis.dom.detectors.form_detector import FormDetector
from src.analyzers.url.dynamic_analysis.dom.detectors.iframe_detector import IframeDetector
from src.analyzers.url.dynamic_analysis.dom.detectors.meta_detector import MetaDetector
from src.analyzers.url.dynamic_analysis.dom.detectors.javascript_detector import JavaScriptDetector
from src.analyzers.url.dynamic_analysis.dom.detectors.script_detector import ScriptDetector
from src.analyzers.url.dynamic_analysis.dom.detectors.resource_detector import ResourceDetector

__all__ = [
    "FormDetector",
    "IframeDetector",
    "MetaDetector",
    "JavaScriptDetector",
    "ScriptDetector",
    "ResourceDetector",
]
