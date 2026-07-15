import httpx
import json

def test_google():
    url = "http://127.0.0.1:8000/api/analyze"
    payload = {"url": "https://google.com", "language": "vi"}
    try:
        resp = httpx.post(url, json=payload, timeout=20.0)
        print(f"Status Code: {resp.status_code}")
        if resp.status_code == 200:
            print("Response JSON:")
            print(json.dumps(resp.json(), indent=2))
        else:
            print(f"Error: {resp.text}")
    except Exception as e:
        print(f"Failed to connect to server: {e}")

if __name__ == "__main__":
    test_google()
