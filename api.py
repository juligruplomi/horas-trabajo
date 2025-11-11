from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

app = FastAPI()

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "API GrupLomi Horas v1.0"}

@app.get("/health")
async def health():
    return JSONResponse({"status": "healthy", "proxy": "connected"})

@app.post("/auth/login")
async def login(data: dict):
    import requests
    import os
    import jwt
    import bcrypt
    from datetime import datetime, timedelta
    
    PROXY_URL = os.getenv("PROXY_URL", "http://185.194.59.40:3001")
    PROXY_API_KEY = os.getenv("PROXY_API_KEY", "GrupLomi2024ProxySecureKey_XyZ789")
    SECRET_KEY = os.getenv("JWT_SECRET_KEY", "HorasTrabajo_JWT_Secret_2025")
    
    email = data.get("email")
    password = data.get("password")
    
    if not email or not password:
        return JSONResponse({"detail": "Email y contraseña requeridos"}, status_code=400)
    
    try:
        response = requests.post(
            f"{PROXY_URL}/query",
            json={"text": "SELECT * FROM usuarios WHERE email = ", "params": [email]},
            headers={"x-api-key": PROXY_API_KEY},
            timeout=10
        )
        rows = response.json().get("rows", [])
        
        if not rows:
            return JSONResponse({"detail": "Credenciales incorrectas"}, status_code=401)
        
        user = dict(rows[0])
        
        try:
            is_valid = bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8'))
        except:
            is_valid = False
        
        if not is_valid:
            return JSONResponse({"detail": "Credenciales incorrectas"}, status_code=401)
        
        if not user.get('activo', True):
            return JSONResponse({"detail": "Usuario desactivado"}, status_code=401)
        
        payload = {
            'user_id': user['id'],
            'email': user['email'],
            'role': user['role'],
            'nombre': user.get('nombre', ''),
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        user.pop('password_hash', None)
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": user
        }
    except Exception as e:
        return JSONResponse({"detail": f"Error: {str(e)}"}, status_code=500)
