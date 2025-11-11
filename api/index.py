from http.server import BaseHTTPRequestHandler
import json
import sys
import os

# Agregar ruta para importar desde la raíz
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from index import handler

# Vercel ya maneja el handler de BaseHTTPRequestHandler automáticamente
