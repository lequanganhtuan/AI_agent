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

async def main():
    if not api_key:
        print("Error: GEMINI_API_KEY not set in environment or .env file.")
        return

    # Use standard Client from google-genai
    client = genai.Client(api_key=api_key)

    # Test 1: Independent SDK Call
    print("\n--- Test 1: Testing Gemini SDK independently ---")
    try:
        start_time = time.perf_counter()
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents="Hello"
        )
        duration = time.perf_counter() - start_time
        print(f"[OK] Success (took {duration:.2f} seconds)")
        print(f"Response: {response.text.strip()}")
    except Exception as e:
        print(f"[FAIL] Failed Test 1: {str(e)}")
        print("\nRoot cause suggestion:")
        print("- Verify that your GEMINI_API_KEY is correct. (If it starts with 'AQ.', ensure it is a valid Gemini Developer key, typically starting with 'AIzaSy'.)")
        print("- Check proxy settings if you are behind an enterprise firewall.")
        return

    # Test 2: Text-only Minimal Prompt
    print("\n--- Test 2: Text-only Minimal Prompt ---")
    try:
        start_time = time.perf_counter()
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents="Hello! Please reply with a simple 'Hello' back."
        )
        duration = time.perf_counter() - start_time
        print(f"[OK] Success (took {duration:.2f} seconds)")
        print(f"Response: {response.text.strip()}")
    except Exception as e:
        print(f"[FAIL] Failed Test 2: {str(e)}")

    # Test 3: Production Prompt without image
    print("\n--- Test 3: Production Prompt without image ---")
    mock_system_prompt = "You are a professional security analysis LLM. Analyze the provided HTML context. Return JSON only. Never speculate."
    mock_user_prompt = "Target URL: https://example.com\nTitle: Demo Page\n\nAnalyze this URL context to check if it impersonates any brand."
    try:
        start_time = time.perf_counter()
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            config=types.GenerateContentConfig(
                system_instruction=mock_system_prompt,
                response_mime_type="application/json"
            ),
            contents=mock_user_prompt
        )
        duration = time.perf_counter() - start_time
        print(f"[OK] Success (took {duration:.2f} seconds)")
        print(f"Response: {response.text.strip()}")
    except Exception as e:
        print(f"[FAIL] Failed Test 3: {str(e)}")

    # Test 4: Image Payload Only
    print("\n--- Test 4: Image Payload Only ---")
    # Tiny 1x1 black PNG
    tiny_png_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
    image_bytes = base64.b64decode(tiny_png_b64)
    try:
        start_time = time.perf_counter()
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=[
                types.Part.from_bytes(
                    data=image_bytes,
                    mime_type="image/png"
                ),
                "Describe this image."
            ]
        )
        duration = time.perf_counter() - start_time
        print(f"[OK] Success (took {duration:.2f} seconds)")
        print(f"Response: {response.text.strip()}")
    except Exception as e:
        print(f"[FAIL] Failed Test 4: {str(e)}")

    # Test 5: Full Prompt + Screenshot
    print("\n--- Test 5: Full Prompt + Tiny Screenshot ---")
    try:
        start_time = time.perf_counter()
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            config=types.GenerateContentConfig(
                system_instruction=mock_system_prompt,
                response_mime_type="application/json"
            ),
            contents=[
                types.Part.from_bytes(
                    data=image_bytes,
                    mime_type="image/png"
                ),
                mock_user_prompt
            ]
        )
        duration = time.perf_counter() - start_time
        print(f"[OK] Success (took {duration:.2f} seconds)")
        print(f"Response: {response.text.strip()}")
    except Exception as e:
        print(f"[FAIL] Failed Test 5: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
