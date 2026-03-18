from flask import Flask, render_template, request, jsonify
import math

app = Flask(__name__)

# Lista de passwords comuns para verificação
COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345", "1234", "qwerty",
    "111111", "1234567", "dragon", "pussy", "123123", "iloveyou", "football",
    "1234567890", "senha", "batman", "superman", "shadow", "sunshine"
]

def get_character_set_size(password):
    """Deteta o tamanho do conjunto de caracteres (N) usado na password."""
    has_lower = any('a' <= char <= 'z' for char in password)
    has_upper = any('A' <= char <= 'Z' for char in password)
    has_digits = any('0' <= char <= '9' for char in password)
    # Considera símbolo qualquer coisa que não seja letra ou dígito
    has_symbols = any(not ('a' <= char.lower() <= 'z' or '0' <= char <= '9') for char in password)

    # Se houver símbolos, assumimos o conjunto de 95 caracteres ASCII imprimíveis para N.
    # Esta é uma simplificação que cobre a maioria dos casos de uso de símbolos.
    if has_symbols:
        return 95

    n = 0
    if has_lower:
        n += 26
    if has_upper:
        n += 26
    if has_digits:
        n += 10
    
    return n if n > 0 else 1 # Evita log(0) se a password estiver vazia

@app.route('/')
def index():
    """Renderiza a página principal."""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_password():
    """
    Endpoint de API para análise de password (validação server-side opcional).
    NOTA DE SEGURANÇA: A password recebida aqui não é logada nem armazenada.
    O cálculo principal é feito no frontend para feedback em tempo real e para
    evitar que a password transite desnecessariamente pela rede.
    Este endpoint serve como uma camada de validação secundária.
    """
    data = request.get_json()
    password = data.get('password', '')

    if not password:
        return jsonify({"error": "Password não fornecida."}), 400

    length = len(password)
    n = get_character_set_size(password)

    # Cálculo de Entropia de Shannon: H = L * log2(N)
    entropy = length * math.log2(n) if n > 1 else 0

    # Estimativa de tempo para cracking
    # Assumindo 10^10 (10 mil milhões) de tentativas por segundo.
    # Dividimos por 2 para obter o tempo médio (ataque pode ter sucesso a meio).
    ATTACKER_SPEED_PER_SECOND = 1e10
    total_combinations = n ** length
    seconds_to_crack = (total_combinations / ATTACKER_SPEED_PER_SECOND) / 2

    # Classificação da força
    if entropy < 28:
        strength_text = "Muito Fraca"
    elif entropy < 36:
        strength_text = "Fraca"
    elif entropy < 60:
        strength_text = "Razoável"
    elif entropy < 128:
        strength_text = "Forte"
    else:
        strength_text = "Muito Forte"

    # Sugestões de melhoria
    suggestions = []
    if length < 12:
        suggestions.append({
            "message": "Aumentar o comprimento para pelo menos 16 caracteres.",
            "impact": f"Aumentar para 16 caracteres com o alfabeto atual (N={n}) aumentaria a entropia para {16 * math.log2(n) if n > 1 else 0:.2f} bits."
        })
    if not any('A' <= char <= 'Z' for char in password):
        new_n = get_character_set_size(password + 'A')
        suggestions.append({
            "message": "Adicionar letras maiúsculas.",
            "impact": f"Isso aumentaria o alfabeto (N) de {n} para {new_n}, resultando em {length * math.log2(new_n) if new_n > 1 else 0:.2f} bits de entropia."
        })
    if not any('0' <= char <= '9' for char in password):
        new_n = get_character_set_size(password + '1')
        suggestions.append({
            "message": "Adicionar números.",
            "impact": f"Isso aumentaria o alfabeto (N) de {n} para {new_n}, resultando em {length * math.log2(new_n) if new_n > 1 else 0:.2f} bits de entropia."
        })
    if not any(not ('a' <= char.lower() <= 'z' or '0' <= char <= '9') for char in password):
        new_n = get_character_set_size(password + '!')
        suggestions.append({
            "message": "Adicionar símbolos (ex: !@#$%^&*).",
            "impact": f"Isso aumentaria o alfabeto (N) de {n} para {new_n}, resultando em {length * math.log2(new_n) if new_n > 1 else 0:.2f} bits de entropia."
        })
    if password.lower() in COMMON_PASSWORDS:
        suggestions.append({
            "message": "Esta password é extremamente comum e pode ser quebrada instantaneamente.",
            "impact": "Use uma frase-passe única e memorável em vez de palavras comuns."
        })

    return jsonify({
        "entropy": round(entropy, 2),
        "crack_time_seconds": seconds_to_crack,
        "strength": strength_text,
        "alphabet_size": n,
        "suggestions": suggestions
    })

if __name__ == '__main__':
    # O ideal é usar um servidor WSGI como Gunicorn ou uWSGI em produção
    app.run(host='0.0.0.0', port=5000, debug=True)
