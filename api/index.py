from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI"}

@app.get("/health")
def health():
    return {"status": "ok", "timestamp": "2025-11-11T12:45:14Z"}
