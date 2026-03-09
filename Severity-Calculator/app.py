# app.py
from flask import Flask, render_template_string, request

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html lang="pt">
<head>
    <meta charset="UTF-8">
    <title>Calculadora de Criticidade NIS2</title>
    <style>
        body { font-family: Arial; background:#f4f6f8; margin:40px; }
        .container { background:white; padding:30px; max-width:600px; margin:auto; border-radius:8px; box-shadow:0 4px 12px rgba(0,0,0,0.1); }
        h1 { margin-bottom:20px; }
        label { font-weight:bold; display:block; margin-top:15px; }
        input, select { width:100%; padding:8px; margin-top:5px; }
        button { margin-top:20px; padding:10px; width:100%; background:#1f2937; color:white; border:none; border-radius:4px; }
        .result { margin-top:20px; padding:15px; background:#eef2ff; border-radius:6px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Calculadora de Criticidade (NIS2)</h1>
        <form method="post">
            <label>Modelo</label>
            <select name="modelo">
                <option value="simples">Modelo Simples (Média)</option>
                <option value="ponderado">Modelo Ponderado (NIS2)</option>
            </select>

            <label>Impacto Operacional (1-5)</label>
            <input type="number" step="0.1" min="1" max="5" name="operacional" required>

            <label>Impacto Legal (1-5)</label>
            <input type="number" step="0.1" min="1" max="5" name="legal" required>

            <label>Impacto CIA (1-5)</label>
            <input type="number" step="0.1" min="1" max="5" name="cia" required>

            <label>Impacto Financeiro (1-5)</label>
            <input type="number" step="0.1" min="1" max="5" name="financeiro" required>

            <label>Impacto Reputacional (1-5)</label>
            <input type="number" step="0.1" min="1" max="5" name="reputacional" required>

            <button type="submit">Calcular</button>
        </form>

        {% if score %}
        <div class="result">
            <strong>Score:</strong> {{ score }} <br>
            <strong>Classificação:</strong> {{ classificacao }}
        </div>
        {% endif %}
    </div>
</body>
</html>
"""

def classificar(score):
    if score >= 4.5:
        return "Crítico"
    elif score >= 3.5:
        return "Alto"
    elif score >= 2.5:
        return "Médio"
    else:
        return "Baixo"

@app.route("/", methods=["GET", "POST"])
def index():
    score = None
    classificacao = None

    if request.method == "POST":
        op = float(request.form["operacional"])
        legal = float(request.form["legal"])
        cia = float(request.form["cia"])
        fin = float(request.form["financeiro"])
        rep = float(request.form["reputacional"])
        modelo = request.form["modelo"]

        if modelo == "simples":
            score = (op + legal + cia + fin + rep) / 5
        else:
            score = (
                (op * 0.35) +
                (cia * 0.25) +
                (legal * 0.20) +
                (fin * 0.10) +
                (rep * 0.10)
            )

        score = round(score, 2)
        classificacao = classificar(score)

    return render_template_string(HTML, score=score, classificacao=classificacao)

if __name__ == "__main__":
    app.run(debug=True)