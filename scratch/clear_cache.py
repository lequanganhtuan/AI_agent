import asyncio
import os
import sys
from dotenv import load_dotenv
# Load environment variables from parent directory .env file
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

# Add src directory to python path
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from src.core.database.firestore_repository import FirestoreRepository
from src.core.settings import settings

async def clear_firestore_collections(db_repo):
    client = db_repo.client
    
    # 1. Clear 'scans' collection (or whatever is configured)
    scans_collection = db_repo.collection_name
    print(f"Fetching documents from Firestore collection: '{scans_collection}'...")
    try:
        scans_count = 0
        async for doc in client.collection(scans_collection).list_documents():
            await doc.delete()
            scans_count += 1
        print(f"Successfully deleted {scans_count} documents from '{scans_collection}'.")
    except Exception as e:
        print(f"Error clearing '{scans_collection}' collection: {str(e)}")

    # 2. Clear Genkit 'cache' collection
    genkit_cache_collection = "cache"
    print(f"Fetching documents from Firestore collection: '{genkit_cache_collection}'...")
    try:
        cache_count = 0
        async for doc in client.collection(genkit_cache_collection).list_documents():
            await doc.delete()
            cache_count += 1
        print(f"Successfully deleted {cache_count} documents from '{genkit_cache_collection}'.")
    except Exception as e:
        print(f"Error clearing '{genkit_cache_collection}' collection: {str(e)}")

def clear_local_cache():
    # Delete artifacts/local_memory_cache.json
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cache_file = os.path.join(base_dir, "artifacts", "local_memory_cache.json")
    
    if os.path.exists(cache_file):
        try:
            os.remove(cache_file)
            print(f"Successfully deleted local cache file: {cache_file}")
        except Exception as e:
            print(f"Error deleting local cache file: {str(e)}")
    else:
        print(f"Local cache file not found, nothing to delete: {cache_file}")

async def main():
    # Load .env variables
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
    
    print("=== Clear Cache Script ===")
    
    # 1. Clear local memory cache file
    clear_local_cache()
    
    # 2. Clear Firestore collection
    db_repo = FirestoreRepository()
    await clear_firestore_collections(db_repo)
    
    print("=== Cache Reset Process Complete ===")

if __name__ == "__main__":
    asyncio.run(main())
