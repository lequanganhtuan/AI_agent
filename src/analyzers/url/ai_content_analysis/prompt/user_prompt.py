import json
from src.analyzers.url.ai_content_analysis.models import AIAnalysisInput
from src.analyzers.url.ai_content_analysis.prompt.schema import LLM_JSON_SCHEMA

MAX_TEXT_LENGTH = 8000

def build_user_prompt(analysis_input: AIAnalysisInput) -> str:
    """Compiles the clean structural input data from AIAnalysisInput into a single,
    cohesive user prompt string with explicit markdown section headings.
    
    The extracted_text is always placed at the absolute end of the prompt and
    truncated to MAX_TEXT_LENGTH to safeguard token capacity.
    """
    sections = []

    # --- TASK ---
    sections.append("### TASK")
    sections.append(
        "Analyze the following website data and provide your security assessment "
        "as a JSON object matching the expected output schema exactly."
    )

    # --- INPUT ---
    sections.append("\n### INPUT")
    sections.append(f"- Target URL: {analysis_input.url}")
    sections.append(f"- Final Landing URL: {analysis_input.final_url}")
    sections.append(f"- Document Title: {analysis_input.page_title}")
    if analysis_input.legitimate_domain:
        sections.append(f"- Suspected Legitimate Domain: {analysis_input.legitimate_domain}")

    # --- METADATA ---
    sections.append("\n### METADATA")
    metadata = analysis_input.metadata
    sections.append(f"- URL Length: {metadata.get('url_length', 'N/A')}")
    sections.append(f"- Language: {metadata.get('page_language', 'N/A')}")
    sections.append(f"- Redirect Count: {metadata.get('redirect_count', 0)}")
    sections.append(f"- Has Login Form: {metadata.get('has_login_form', False)}")
    sections.append(f"- Has Payment Form: {metadata.get('has_payment_form', False)}")
    sections.append(f"- Has OTP Form: {metadata.get('has_otp_form', False)}")

    # --- SIGNALS ---
    sections.append("\n### SIGNALS")
    if analysis_input.important_signals:
        for signal in analysis_input.important_signals:
            sections.append(f"- {signal}")
    else:
        sections.append("- No signals detected.")

    # --- STATIC ANALYSIS ---
    sections.append("\n### STATIC ANALYSIS")
    if analysis_input.static_summary:
        sections.append(analysis_input.static_summary)
    else:
        sections.append("No static analysis summary available.")

    # --- THREAT INTELLIGENCE ---
    sections.append("\n### THREAT INTELLIGENCE")
    if analysis_input.threat_summary:
        sections.append(analysis_input.threat_summary)
    else:
        sections.append("No threat intelligence summary available.")

    # --- DYNAMIC ANALYSIS ---
    sections.append("\n### DYNAMIC ANALYSIS")
    if analysis_input.dynamic_summary:
        sections.append(analysis_input.dynamic_summary)
    else:
        sections.append("No dynamic analysis summary available.")

    # --- VISIBLE WEBSITE CONTENT (always last) ---
    sections.append("\n### VISIBLE WEBSITE CONTENT")
    text = analysis_input.extracted_text or ""
    if len(text) > MAX_TEXT_LENGTH:
        text = text[:MAX_TEXT_LENGTH] + "\n[...TRUNCATED]"
    if text:
        sections.append(text)
    else:
        sections.append("No visible text content extracted.")

    # --- EXPECTED OUTPUT ---
    sections.append("\n### EXPECTED OUTPUT")
    sections.append(
        "You must return your response as a JSON object matching this exact schema:"
    )
    sections.append(LLM_JSON_SCHEMA)

    return "\n".join(sections)
