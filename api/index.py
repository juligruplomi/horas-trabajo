from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "API GrupLomi"}

@app.get("/health")
async def health():
    return JSONResponse({"status": "healthy", "proxy": "connected"})
