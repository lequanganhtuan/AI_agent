from __future__ import annotations
from src.core.models import NetworkAnalysis, DynamicSignal
from src.analyzers.url.dynamic_analysis.config import DynamicAnalysisConfig, DynamicSignalType, SIGNAL_SEVERITY

class NetworkSignalGenerator:
    """Sub-generator to extract dynamic signals from NetworkAnalysis data."""

    @staticmethod
    def generate(analysis: NetworkAnalysis, config: DynamicAnalysisConfig) -> list[DynamicSignal]:
        signals = []

        if len(analysis.third_party_domains) > 0:
            sig_type = DynamicSignalType.THIRD_PARTY_DOMAIN
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=1.0,
                evidence=f"Detected {len(analysis.third_party_domains)} third-party domains."
            ))

        if len(analysis.cdn_domains) > 0:
            sig_type = DynamicSignalType.CDN_USAGE
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=1.0,
                evidence=f"Detected {len(analysis.cdn_domains)} CDN domains."
            ))

        if len(analysis.api_endpoints) > 0:
            sig_type = DynamicSignalType.API_USAGE
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=1.0,
                evidence=f"Detected {len(analysis.api_endpoints)} API endpoints."
            ))

        if len(analysis.websocket_connections) > 0:
            sig_type = DynamicSignalType.WEBSOCKET_USAGE
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=1.0,
                evidence=f"Detected {len(analysis.websocket_connections)} WebSocket connections."
            ))

        if len(analysis.failed_requests) > 0:
            sig_type = DynamicSignalType.FAILED_REQUEST
            signals.append(DynamicSignal(
                signal=sig_type,
                severity=SIGNAL_SEVERITY[sig_type],
                confidence=1.0,
                evidence=f"Detected {len(analysis.failed_requests)} failed network requests."
            ))

        return signals
