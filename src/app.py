import os
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src.analyzers.url.preprocessing.url_analyzer import URLAnalyzer
from src.analyzers.url.static.static_url_analyzer import StaticURLAnalyzer
from src.core.models import StaticAnalysisResult

app = FastAPI(title="URL Analyzer Web Demo")

# Determine the absolute path to the static folder
base_dir = os.path.dirname(os.path.abspath(__file__))
static_dir = os.path.join(base_dir, "static")

# Mount static files to serve CSS, JS, etc.
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

class AnalyzeRequest(BaseModel):
    url: str

@app.get("/", response_class=HTMLResponse)
async def read_root():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Static directory not found!</h1>"

@app.post("/api/analyze")
async def analyze_url(req: AnalyzeRequest):
    try:
        url_analyzer = URLAnalyzer()
        static_analyzer = StaticURLAnalyzer()
        
        # 1. Preprocessing
        validation_result = url_analyzer.analyze(req.url)
        
        if not validation_result.valid:
            # If validation fails, return an error
            raise HTTPException(status_code=400, detail=validation_result.error_message or "URL validation failed.")
            
        # 2. Static Analysis
        static_result = static_analyzer.analyze(validation_result)
        
        # We can return the model directly, FastAPI will serialize it
        return {
            "validation": validation_result.model_dump(),
            "static": static_result.model_dump()
        }
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))
