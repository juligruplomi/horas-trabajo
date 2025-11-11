from http.server import BaseHTTPRequestHandler
import json
import urllib.parse
import datetime
import os
from typing import Dict, Any, Optional
import jwt
import bcrypt
import requests

PROXY_URL = os.getenv("PROXY_URL", "http://185.194.59.40:3001")
PROXY_API_KEY = os.getenv("PROXY_API_KEY", "GrupLomi2024ProxySecureKey_XyZ789")
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "HorasTrabajo_JWT_Secret_2025")
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24

def db_query(text: str, params: list = None):
    try:
        response = requests.post(
            f"{PROXY_URL}/query",
            json={"text": text, "params": params or []},
            headers={"x-api-key": PROXY_API_KEY},
            timeout=10
        )
        response.raise_for_status()
        data = response.json()
        return data.get("rows", [])
    except Exception as e:
        print(f"Error en db_query: {e}")
        return []

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except:
        return False

def create_token(user_data: Dict) -> str:
    payload = {
        'user_id': user_data['id'],
        'email': user_data['email'],
        'role': user_data['role'],
        'nombre': user_data.get('nombre', ''),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=TOKEN_EXPIRE_HOURS)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> Optional[Dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except:
        return None

def is_admin(user_token: Dict) -> bool:
    return user_token and user_token.get('role') == 'admin'

def is_supervisor(user_token: Dict) -> bool:
    return user_token and user_token.get('role') in ['admin', 'supervisor']

def is_operario(user_token: Dict) -> bool:
    return user_token and user_token.get('role') in ['admin', 'supervisor', 'operario']

class handler(BaseHTTPRequestHandler):
    def _set_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    
    def _send_json_response(self, data: Any, status_code: int = 200):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2, default=str).encode('utf-8'))
    
    def _get_request_data(self) -> Dict:
        try:
            content_length = int(self.headers.get('content-length', 0))
            if content_length > 0:
                body = self.rfile.read(content_length)
                return json.loads(body.decode('utf-8'))
            return {}
        except:
            return {}
    
    def _verify_token(self) -> Optional[Dict]:
        try:
            auth_header = self.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return None
            token = auth_header.split(' ')[1]
            return verify_token(token)
        except:
            return None

    def do_OPTIONS(self):
        self.send_response(200)
        self._set_cors_headers()
        self.end_headers()

    def do_GET(self):
        try:
            parsed_path = urllib.parse.urlparse(self.path)
            path = parsed_path.path
            
            if path == '/' or path == '/api':
                self._send_json_response({
                    "message": "API de Control de Horas GrupLomi v1.0",
                    "status": "online",
                    "version": "1.0.0",
                    "database": "PostgreSQL via Proxy"
                })
            elif path == '/health':
                try:
                    response = requests.get(f"{PROXY_URL}/health", timeout=5)
                    proxy_status = "connected" if response.status_code == 200 else "error"
                except:
                    proxy_status = "disconnected"
                self._send_json_response({"status": "healthy" if proxy_status == "connected" else "unhealthy", "proxy_status": proxy_status})
            elif path == '/auth/me':
                user_token = self._verify_token()
                if not user_token:
                    self._send_json_response({"error": "Token inválido"}, 401)
                    return
                rows = db_query("SELECT * FROM usuarios WHERE id = ", [user_token['user_id']])
                if rows:
                    user = dict(rows[0])
                    user.pop('password_hash', None)
                    self._send_json_response(user)
                else:
                    self._send_json_response({"error": "Usuario no encontrado"}, 404)
            elif path == '/horas':
                user_token = self._verify_token()
                if not user_token:
                    self._send_json_response({"error": "Token requerido"}, 401)
                    return
                if user_token['role'] == 'operario':
                    rows = db_query("SELECT * FROM horas_trabajadas WHERE usuario_id = $1 ORDER BY fecha_trabajo DESC", [user_token['user_id']])
                else:
                    rows = db_query("SELECT * FROM horas_trabajadas ORDER BY fecha_trabajo DESC")
                self._send_json_response([dict(r) for r in rows])
            elif path == '/usuarios':
                user_token = self._verify_token()
                if not user_token or not is_admin(user_token):
                    self._send_json_response({"error": "Sin permisos"}, 403)
                    return
                rows = db_query("SELECT id, email, nombre, apellidos, role, departamento, telefono, activo FROM usuarios ORDER BY nombre")
                self._send_json_response([dict(r) for r in rows])
            elif path == '/roles':
                user_token = self._verify_token()
                if not user_token:
                    self._send_json_response({"error": "Token requerido"}, 401)
                    return
                roles = [
                    {"id": "admin", "nombre": "Administrador"},
                    {"id": "supervisor", "nombre": "Supervisor"},
                    {"id": "operario", "nombre": "Operario"}
                ]
                self._send_json_response(roles)
            elif path == '/proyectos':
                user_token = self._verify_token()
                if not user_token:
                    self._send_json_response({"error": "Token requerido"}, 401)
                    return
                rows = db_query("SELECT * FROM proyectos WHERE estado = 'activo' ORDER BY nombre")
                self._send_json_response([dict(r) for r in rows])
            elif path == '/reportes/dashboard':
                user_token = self._verify_token()
                if not user_token:
                    self._send_json_response({"error": "Token requerido"}, 401)
                    return
                total_horas_rows = db_query("SELECT SUM(horas_trabajadas) as total FROM horas_trabajadas")
                total_horas = float(total_horas_rows[0]['total'] or 0) if total_horas_rows else 0
                pendientes_rows = db_query("SELECT COUNT(*) as total FROM horas_trabajadas WHERE estado = 'pendiente'")
                pendientes = pendientes_rows[0]['total'] if pendientes_rows else 0
                self._send_json_response({"total_horas": total_horas, "pendientes": pendientes})
            elif path == '/config':
                self._send_json_response({"empresa_nombre": "GrupLomi", "color_primario": "#0066CC"})
            else:
                self._send_json_response({"error": "Endpoint no encontrado"}, 404)
        except Exception as e:
            self._send_json_response({"error": "Error interno", "details": str(e)}, 500)

    def do_POST(self):
        try:
            parsed_path = urllib.parse.urlparse(self.path)
            path = parsed_path.path
            data = self._get_request_data()
            
            if path == '/auth/login':
                email = data.get('email')
                password = data.get('password')
                if not email or not password:
                    self._send_json_response({"error": "Email y contraseña requeridos"}, 400)
                    return
                rows = db_query("SELECT * FROM usuarios WHERE email = $1", [email])
                if not rows:
                    self._send_json_response({"error": "Credenciales incorrectas"}, 401)
                    return
                user = dict(rows[0])
                if not verify_password(password, user['password_hash']):
                    self._send_json_response({"error": "Credenciales incorrectas"}, 401)
                    return
                if not user.get('activo', True):
                    self._send_json_response({"error": "Usuario desactivado"}, 401)
                    return
                token = create_token(user)
                user.pop('password_hash', None)
                self._send_json_response({"access_token": token, "token_type": "bearer", "user": user})
            elif path == '/horas':
                user_token = self._verify_token()
                if not user_token or not is_operario(user_token):
                    self._send_json_response({"error": "Token requerido"}, 401)
                    return
                rows = db_query(
                    "INSERT INTO horas_trabajadas (usuario_id, tipo_trabajo, proyecto_obra, fecha_trabajo, horas_trabajadas, descripcion, estado) VALUES ($1, $2, $3, $4, $5, $6, 'pendiente') RETURNING *",
                    [user_token['user_id'], data.get('tipo_trabajo'), data.get('proyecto_obra'), data.get('fecha_trabajo'), data.get('horas_trabajadas'), data.get('descripcion', '')]
                )
                if rows:
                    self._send_json_response(dict(rows[0]), 201)
                else:
                    self._send_json_response({"error": "Error al registrar horas"}, 500)
            else:
                self._send_json_response({"error": "Endpoint no encontrado"}, 404)
        except Exception as e:
            self._send_json_response({"error": "Error interno", "details": str(e)}, 500)

    def do_PUT(self):
        try:
            parsed_path = urllib.parse.urlparse(self.path)
            path = parsed_path.path
            data = self._get_request_data()
            user_token = self._verify_token()
            if not user_token:
                self._send_json_response({"error": "Token requerido"}, 401)
                return
            
            if path.startswith('/horas/'):
                horas_id = path.split('/')[-1]
                horas_rows = db_query("SELECT * FROM horas_trabajadas WHERE id = $1", [horas_id])
                if not horas_rows:
                    self._send_json_response({"error": "Registro no encontrado"}, 404)
                    return
                horas = dict(horas_rows[0])
                if user_token['role'] == 'operario' and horas['usuario_id'] != user_token['user_id']:
                    self._send_json_response({"error": "Sin permisos"}, 403)
                    return
                if data.get('estado') and is_supervisor(user_token):
                    updated_rows = db_query(
                        "UPDATE horas_trabajadas SET estado = $1, validado_por = $2, fecha_validacion = NOW() WHERE id = $3 RETURNING *",
                        [data['estado'], user_token['user_id'], horas_id]
                    )
                    if updated_rows:
                        self._send_json_response(dict(updated_rows[0]))
                    else:
                        self._send_json_response({"error": "Error al actualizar"}, 500)
                else:
                    updated_rows = db_query(
                        "UPDATE horas_trabajadas SET horas_trabajadas = $1, descripcion = $2, fecha_modificacion = NOW() WHERE id = $3 RETURNING *",
                        [data.get('horas_trabajadas'), data.get('descripcion', ''), horas_id]
                    )
                    if updated_rows:
                        self._send_json_response(dict(updated_rows[0]))
                    else:
                        self._send_json_response({"error": "Error al actualizar"}, 500)
            else:
                self._send_json_response({"error": "Endpoint no encontrado"}, 404)
        except Exception as e:
            self._send_json_response({"error": "Error interno", "details": str(e)}, 500)

    def do_DELETE(self):
        try:
            parsed_path = urllib.parse.urlparse(self.path)
            path = parsed_path.path
            user_token = self._verify_token()
            if not user_token:
                self._send_json_response({"error": "Token requerido"}, 401)
                return
            
            if path.startswith('/horas/'):
                horas_id = path.split('/')[-1]
                horas_rows = db_query("SELECT * FROM horas_trabajadas WHERE id = $1", [horas_id])
                if not horas_rows:
                    self._send_json_response({"error": "Registro no encontrado"}, 404)
                    return
                horas = dict(horas_rows[0])
                if user_token['role'] == 'operario' and horas['usuario_id'] != user_token['user_id']:
                    self._send_json_response({"error": "Sin permisos"}, 403)
                    return
                db_query("DELETE FROM horas_trabajadas WHERE id = $1", [horas_id])
                self._send_json_response({"message": "Registro eliminado correctamente"})
            else:
                self._send_json_response({"error": "Endpoint no encontrado"}, 404)
        except Exception as e:
            self._send_json_response({"error": "Error interno", "details": str(e)}, 500)

    def log_message(self, format, *args):
        pass
