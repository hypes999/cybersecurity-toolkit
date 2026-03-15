import http.server
import socketserver
import urllib.parse
import json
import os
from core import BreachChecker

# Configurações
PORT = 8080
DEFAULT_HASH_FILE = "sample_hashes.txt"

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="pt">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Leak Checker - Web</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; max-width: 800px; margin: 0 auto; padding: 20px; background-color: #f4f4f9; color: #333; }
        .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="password"], input[type="text"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        button { display: block; width: 100%; padding: 12px; background-color: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
        button:hover { background-color: #2980b9; }
        #result { margin-top: 20px; padding: 15px; border-radius: 4px; display: none; }
        .pwned { background-color: #e74c3c; color: white; }
        .safe { background-color: #2ecc71; color: white; }
        .info { font-size: 0.9em; color: #7f8c8d; margin-top: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Password Leak Checker</h1>
        <p>Verifique se a sua password foi vazada. A verificação é feita localmente no servidor.</p>
        
        <div class="form-group">
            <label for="password">Introduza a Password:</label>
            <input type="password" id="password" placeholder="Sua password secreta...">
        </div>
        
        <div class="form-group">
            <label for="hash_file">Ficheiro de Hashes (Local):</label>
            <input type="text" id="hash_file" value="{default_hash_file}">
        </div>
        
        <button onclick="checkPassword()">Verificar Agora</button>
        
        <div id="result"></div>
        <p class="info">Nota: Esta interface web é apenas para demonstração local e usa apenas a biblioteca standard do Python.</p>
    </div>

    <script>
        async function checkPassword() {
            const password = document.getElementById('password').value;
            const hashFile = document.getElementById('hash_file').value;
            const resultDiv = document.getElementById('result');
            
            if (!password) {
                alert('Por favor, introduza uma password.');
                return;
            }

            try {
                const response = await fetch('/check', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password, hash_file: hashFile })
                });
                
                const data = await response.json();
                
                resultDiv.style.display = 'block';
                if (data.error) {
                    resultDiv.className = 'pwned';
                    resultDiv.innerHTML = `<strong>Erro:</strong> ${data.error}`;
                } else if (data.found) {
                    resultDiv.className = 'pwned';
                    resultDiv.innerHTML = `<strong>[!!!] PWNED!</strong> Esta password foi encontrada no dataset de leaks.`;
                } else {
                    resultDiv.className = 'safe';
                    resultDiv.innerHTML = `<strong>[✓] SEGURA!</strong> Esta password não foi encontrada no dataset.`;
                }
            } catch (e) {
                resultDiv.style.display = 'block';
                resultDiv.className = 'pwned';
                resultDiv.innerHTML = '<strong>Erro na comunicação com o servidor.</strong>';
            }
        }
    </script>
</body>
</html>
"""

class LeakCheckerHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            # Substituir manualmente apenas o placeholder necessário para evitar erros de formatação com chavetas do JS/CSS
            content = HTML_TEMPLATE.replace("{default_hash_file}", DEFAULT_HASH_FILE)
            self.wfile.write(content.encode('utf-8'))
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == '/check':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            params = json.loads(post_data.decode('utf-8'))
            
            password = params.get('password', '')
            hash_file = params.get('hash_file', DEFAULT_HASH_FILE)
            
            try:
                # Verificar se o ficheiro existe antes de inicializar o checker
                if not os.path.exists(hash_file):
                    raise FileNotFoundError(f"Ficheiro não encontrado: {hash_file}")
                
                checker = BreachChecker(hash_file)
                result = checker.check_password(password)
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(result).encode('utf-8'))
            except Exception as e:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
        else:
            self.send_error(404)

if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), LeakCheckerHandler) as httpd:
        print(f"Servidor Web iniciado em http://localhost:{PORT}")
        print(f"Pressione Ctrl+C para parar.")
        httpd.serve_forever()
