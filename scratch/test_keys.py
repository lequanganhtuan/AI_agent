import os
import asyncio
import httpx
from dotenv import load_dotenv

# Load môi trường
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(base_dir, ".env"))

# Danh sách cấu hình các dịch vụ
SERVICES = {
    "VirusTotal": {"key": os.getenv("VIRUSTOTAL_API_KEY"), "func": "test_virustotal"},
    "Google Safe Browsing": {"key": os.getenv("GOOGLE_SAFE_BROWSING_API_KEY"), "func": "test_google_safe_browsing"},
    "URLScan": {"key": os.getenv("URLSCAN_API_KEY"), "func": "test_urlscan"},
    "URLHaus": {"key": os.getenv("URLHAUS_API_KEY"), "func": "test_urlhaus"},
    "AbuseIPDB": {"key": os.getenv("ABUSEIPDB_API_KEY"), "func": "test_abuseipdb"},
}

# --- Các hàm kiểm tra API (Client được truyền vào) ---

async def test_virustotal(client, key):
    if not key: return "Not Configured", "Skipped"
    resp = await client.get("https://www.virustotal.com/api/v3/users/me", headers={"x-apikey": key})
    return ("Valid", "OK") if resp.status_code == 200 else ("Invalid", f"HTTP {resp.status_code}")

async def test_google_safe_browsing(client, key):
    if not key: return "Not Configured", "Skipped"
    url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}"
    resp = await client.post(url, json={"client": {"clientId": "tester", "clientVersion": "1.0"}, "threatInfo": {"threatTypes": ["MALWARE"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": "http://example.com"}]}})
    return ("Valid", "OK") if resp.status_code == 200 else ("Invalid", f"HTTP {resp.status_code}")

async def test_urlscan(client, key):
    if not key: return "Not Configured", "Skipped"
    resp = await client.get("https://urlscan.io/api/v1/search/?q=domain:google.com", headers={"API-Key": key})
    return ("Valid", "OK") if resp.status_code == 200 else ("Invalid", f"HTTP {resp.status_code}")

async def test_urlhaus(client, key):
    resp = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": "http://google.com"}, headers={"Auth-Key": key} if key else {})
    return ("Valid", "OK") if resp.status_code == 200 else ("Invalid", f"HTTP {resp.status_code}")

async def test_abuseipdb(client, key):
    if not key: return "Not Configured", "Skipped"
    try:
        resp = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": "8.8.8.8"}
        )
        data = resp.json()
        
        if resp.status_code == 200 and "data" in data:
            return "Valid", "OK"
        else:
            if "errors" in data and len(data["errors"]) > 0:
                error_msg = data["errors"][0].get("detail", f"HTTP {resp.status_code}")
            else:
                error_msg = f"HTTP {resp.status_code}"
            return "Invalid", error_msg
    except Exception as e:
        return "Error", str(e)

async def main():
    print(f"{'SERVICE':<25} | {'STATUS':<15} | {'DETAILS'}")
    print("-" * 60)
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        tasks = []
        names = []
        for name, info in SERVICES.items():
            func = globals()[info["func"]]
            tasks.append(func(client, info["key"]))
            names.append(name)
        
        results = await asyncio.gather(*tasks)
        
        for name, (status, detail) in zip(names, results):
            print(f"{name:<25} | {status:<15} | {detail}")

if __name__ == "__main__":
    asyncio.run(main())