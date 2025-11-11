import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

# Importar handler
from index import handler as BaseHandler

# Wrapper para Vercel
async def handler(request):
    """Wrapper ASGI para Vercel"""
    import json
    from urllib.parse import urlparse
    
    path = request.path
    method = request.method
    
    # Crear un objeto fake para BaseHTTPRequestHandler
    class FakeRequest:
        def __init__(self, req):
            self.path = req.path
            self.method = req.method
            self.headers = dict(req.headers)
            self.body = req.body if hasattr(req, 'body') else b''
    
    fake_req = FakeRequest(request)
    
    # Llamar al handler original
    response = await BaseHandler(fake_req, None, None)
    
    return response
