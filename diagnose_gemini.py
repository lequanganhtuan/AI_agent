import os
import time
import asyncio
import base64
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")
print(f"Loaded GEMINI_API_KEY: {api_key[:12] if api_key else 'None'}...")

# Strict JSON Schema matching the production LLMOutput
RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "website_purpose": {"type": "STRING"},
        "is_phishing": {"type": "BOOLEAN"},
        "fraud_category": {"type": "STRING", "enum": ["LEGITIMATE", "PHISHING", "BRAND_IMPERSONATION", "SCAM", "MALWARE_DISTRIBUTION"]},
        "detected_brand": {"type": "STRING"},
        "brand_confidence": {"type": "NUMBER"},
        "reasoning": {"type": "ARRAY", "items": {"type": "STRING"}},
        "summary": {"type": "STRING"},
        "recommended_action": {"type": "STRING", "enum": ["ALLOW", "WARN", "BLOCK", "MONITOR"]},
        "risk_level": {"type": "STRING", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
        "findings": {"type": "ARRAY", "items": {"type": "STRING"}}
    },
    "required": [
        "website_purpose", "is_phishing", "fraud_category", "detected_brand",
        "brand_confidence", "reasoning", "summary", "recommended_action", "risk_level", "findings"
    ]
}

SYSTEM_PROMPT = "You are a professional security analysis LLM. Analyze the provided URL context and return JSON matching the schema."
USER_PROMPT_PRODUCTION = "Target URL: https://google.com\nTitle: Google\n\nAnalyze this URL context to check if it impersonates any brand."

async def run_step(step_name, fn):
    print(f"\n--- {step_name} ---")
    start = time.perf_counter()
    try:
        res = await fn()
        duration = time.perf_counter() - start
        print(f"[OK] Success (took {duration:.2f} seconds)")
        print(f"Response: {res[:200]}...")
        return True
    except Exception as e:
        duration = time.perf_counter() - start
        print(f"[FAIL] Failed after {duration:.2f} seconds: {str(e)}")
        return False

async def main():
    if not api_key:
        print("Error: GEMINI_API_KEY not set in environment or .env file.")
        return

    client = genai.Client(api_key=api_key)
    model = "gemini-2.5-flash"

    # Step 1: Independent Gemini SDK Test (Async)
    async def step1():
        response = await client.aio.models.generate_content(
            model=model,
            contents="Hello"
        )
        return response.text or ""
    
    s1_ok = await run_step("Step 1: Independent Gemini SDK Test (Async)", step1)
    if not s1_ok:
        print("\nStep 1 Failed. Stopping diagnostics. Check your API key, internet connection, or quota limits.")
        return

    # Step 2: Test the Project with a Minimal Prompt
    async def step2():
        response = await client.aio.models.generate_content(
            model=model,
            contents="Hello"
        )
        return response.text or ""
    
    await run_step("Step 2: Project with a Minimal Prompt", step2)

    # Step 3: Reintroduce the System Prompt
    async def step3():
        response = await client.aio.models.generate_content(
            model=model,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT
            ),
            contents="Hello"
        )
        return response.text or ""

    await run_step("Step 3: Reintroduce the System Prompt", step3)

    # Step 4: Reintroduce the response_schema
    async def step4():
        response = await client.aio.models.generate_content(
            model=model,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                response_mime_type="application/json",
                response_schema=RESPONSE_SCHEMA
            ),
            contents="Hello"
        )
        return response.text or ""

    await run_step("Step 4: Reintroduce the response_schema", step4)

    # Step 5: Reintroduce the Actual User Prompt
    async def step5():
        response = await client.aio.models.generate_content(
            model=model,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                response_mime_type="application/json",
                response_schema=RESPONSE_SCHEMA
            ),
            contents=USER_PROMPT_PRODUCTION
        )
        return response.text or ""

    await run_step("Step 5: Reintroduce the Actual User Prompt", step5)

    # Step 6: Finally, Reintroduce the Screenshot
    tiny_png_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
    image_bytes = base64.b64decode(tiny_png_b64)
    image_part = types.Part.from_bytes(data=image_bytes, mime_type="image/png")

    async def step6():
        response = await client.aio.models.generate_content(
            model=model,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                response_mime_type="application/json",
                response_schema=RESPONSE_SCHEMA
            ),
            contents=[USER_PROMPT_PRODUCTION, image_part]
        )
        return response.text or ""

    await run_step("Step 6: Finally, Reintroduce the Screenshot", step6)

if __name__ == "__main__":
    asyncio.run(main())
