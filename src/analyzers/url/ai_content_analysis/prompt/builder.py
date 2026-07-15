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

    # 3. Handle translation instruction and 5-item limit instruction in system prompt
    lang_name = "Vietnamese" if getattr(analysis_input, "language", "vi") == "vi" else "English"
    custom_system_prompt = (
        SYSTEM_PROMPT +
        f"\n\nIMPORTANT LANGUAGE REQUIREMENT:\n"
        f"You MUST write the output values for the following JSON fields in the requested language: {lang_name}.\n"
        f"- `website_purpose`\n"
        f"- `detected_brand` (if localized)\n"
        f"- `summary`\n"
        f"- `reasoning` (all bullet items must be in {lang_name})\n"
        f"- `findings` (all bullet items must be in {lang_name})\n"
        f"- The `description` of each signal in the `signals` list.\n\n"
        f"IMPORTANT LENGTH LIMITATION:\n"
        f"To ensure a concise report, you MUST limit the `reasoning` list, `findings` list, and the `signals` list "
        f"to a MAXIMUM of 5 of the most important items each. Do not exceed 5 items under any circumstances.\n\n"
        f"IMPORTANT SEPARATION OF CONCERNS:\n"
        f"You MUST strictly differentiate between `reasoning` and `findings` to avoid redundancy:\n"
        f"- `reasoning`: Explain the safety/threat logic and psychological intent (e.g., 'The typosquatted domain combined with login forms attempts to trick users into entering credentials').\n"
        f"- `findings`: List only concrete, physical visual or textual evidence discovered on the page (e.g., 'Cloned PayPal logo', 'Form input labeled password', 'Countdown timer')."
    )

    # 4. Construct and return PromptRequest
    return PromptRequest(
        system_prompt=custom_system_prompt,
        user_prompt=user_prompt,
        response_schema=LLMOutput,
        vision_enabled=vision_enabled,
        screenshot_base64=analysis_input.screenshot_path
    )



