import httpx
import time

def test_cache():
    url = "http://127.0.0.1:8000/api/analyze"
    # Use a real domain to run the full pipeline once and cache the result
    payload = {"url": "https://example.com"}
    
    print("Sending Request 1 (first run)...")
    start = time.time()
    try:
        r = httpx.post(url, json=payload, timeout=20.0)
        print(f"Status: {r.status_code}")
        print(f"Time taken: {time.time() - start:.2f}s")
        data = r.json()
        print(f"ID: {data.get('id')}")
        print(f"Cache key: {data.get('cache_key')}")
    except Exception as e:
        print(f"Error: {e}")
        return

    print("\nSending Request 2 (repeat run)...")
    start = time.time()
    try:
        r = httpx.post(url, json=payload, timeout=20.0)
        print(f"Status: {r.status_code}")
        print(f"Time taken: {time.time() - start:.2f}s")
        data = r.json()
        print(f"ID: {data.get('id')}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Wait a second for uvicorn to reload changes
    time.sleep(2.0)
    test_cache()
