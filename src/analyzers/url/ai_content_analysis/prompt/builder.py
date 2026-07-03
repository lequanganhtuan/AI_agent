from src.analyzers.url.ai_content_analysis.models import AIAnalysisInput, PromptRequest, LLMOutput
from src.analyzers.url.ai_content_analysis.prompt.system_prompt import SYSTEM_PROMPT
from src.analyzers.url.ai_content_analysis.prompt.user_prompt import build_user_prompt

def build_prompt(analysis_input: AIAnalysisInput) -> PromptRequest:
    """Acts as the functional orchestration entry point for the prompt generation layer.
    
    Assembles the system prompt and user prompt into a PromptRequest.
    Computes vision_enabled dynamically based on screenshot_path availability.
    
    The system prompt is passed as an absolute static constant.
    The JSON schema is bound to the user execution layer via user_prompt.
    The response_schema is passed as a native structured output constraint
    for downstream AI Client SDK handling.
    
    This function is strictly a stateless text compilation component:
    - Does NOT parse or evaluate JSON strings.
    - Does NOT call any live AI models or dispatch network requests.
    - Does NOT wrap operations inside retry loops.
    - Does NOT execute downstream schema validation tests.
    """
    # 1. User prompt (compiled from AIAnalysisInput, includes schema instruction)
    user_prompt = build_user_prompt(analysis_input)

    # 2. Vision API activation trigger
    vision_enabled = analysis_input.screenshot_path is not None

    # 3. Construct and return PromptRequest
    return PromptRequest(
        system_prompt=SYSTEM_PROMPT,
        user_prompt=user_prompt,
        response_schema=LLMOutput,
        vision_enabled=vision_enabled
    )

