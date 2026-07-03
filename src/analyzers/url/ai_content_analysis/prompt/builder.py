from src.analyzers.url.ai_content_analysis.models import AIAnalysisInput, PromptRequest, LLMOutput
from src.analyzers.url.ai_content_analysis.prompt.system_prompt import SYSTEM_PROMPT
from src.analyzers.url.ai_content_analysis.prompt.user_prompt import build_user_prompt
from src.analyzers.url.ai_content_analysis.prompt.schema import LLM_JSON_SCHEMA

def build_prompt(analysis_input: AIAnalysisInput) -> PromptRequest:
    """Acts as the functional orchestration entry point for the prompt generation layer.
    
    Assembles the system prompt, user prompt, and JSON schema into a PromptRequest.
    Computes vision_enabled dynamically based on screenshot_path availability.
    
    This function is strictly a stateless text compilation component:
    - Does NOT parse or evaluate JSON strings.
    - Does NOT call any live AI models or dispatch network requests.
    - Does NOT wrap operations inside retry loops.
    - Does NOT execute downstream schema validation tests.
    """
    # 1. System prompt (static constant)
    system_prompt = SYSTEM_PROMPT

    # 2. User prompt (compiled from AIAnalysisInput)
    user_prompt = build_user_prompt(analysis_input)

    # 3. Append JSON schema instruction to system prompt
    system_prompt_with_schema = (
        f"{system_prompt}\n\n"
        f"You must return your response as a JSON object matching this exact schema:\n"
        f"{LLM_JSON_SCHEMA}"
    )

    # 4. Vision API activation trigger
    vision_enabled = analysis_input.screenshot_path is not None

    # 5. Construct and return PromptRequest
    return PromptRequest(
        system_prompt=system_prompt_with_schema,
        user_prompt=user_prompt,
        response_schema=LLMOutput,
        vision_enabled=vision_enabled
    )
