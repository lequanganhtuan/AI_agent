from src.analyzers.url.ai_content_analysis.parser.validator import AIResponseValidator
from src.analyzers.url.ai_content_analysis.parser.normalizer import AIResponseNormalizer
from src.analyzers.url.ai_content_analysis.parser.parser import AIResponseParser
from src.analyzers.url.ai_content_analysis.signal.mapper import AISignalMapper
from src.analyzers.url.ai_content_analysis.signal.generator import AISignalGenerator
from src.analyzers.url.ai_content_analysis.risk.calculator import AIRiskCalculator
from src.analyzers.url.ai_content_analysis.risk.engine import AIRiskEngine
from src.analyzers.url.ai_content_analysis.client.gemini_client import GeminiClient
from src.analyzers.url.ai_content_analysis.service import AIAnalysisService

def create_ai_analysis_service() -> AIAnalysisService:
    """Creates and returns a fully initialized and wired AIAnalysisService instance.
    
    Ensures that vendor client swaps do not necessitate modifying orchestrator components.
    """
    # Parser pipeline components
    validator = AIResponseValidator()
    normalizer = AIResponseNormalizer()
    parser = AIResponseParser(validator=validator, normalizer=normalizer)
    
    # Signal generation components
    mapper = AISignalMapper()
    signal_generator = AISignalGenerator(mapper=mapper)
    
    # Risk computation engine components
    calculator = AIRiskCalculator()
    risk_engine = AIRiskEngine(calculator=calculator)
    
    # Gemini client connection instance
    client = GeminiClient()
    
    return AIAnalysisService(
        client=client,
        parser=parser,
        signal_generator=signal_generator,
        risk_engine=risk_engine
    )
