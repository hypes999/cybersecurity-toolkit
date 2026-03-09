# Calculadora de Criticidade (NIS2)

Uma pequena aplicação web em Flask que calcula um **score de criticidade** com base em 5 impactos (operacional, legal, CIA, financeiro e reputacional). A partir do score é gerada uma **classificação** de criticidade (Baixo / Médio / Alto / Crítico).

---

## Como funciona

A aplicação oferece dois modos de cálculo:

- **Modelo Simples (Média)**: faz a média simples dos 5 valores inseridos.
- **Modelo Ponderado (NIS2)**: aplica pesos diferentes para cada impacto, conforme sugerido pelo NIS2.

### Classificação (resultado)
- `Crítico` (score >= 4.5)
- `Alto` (score >= 3.5)
- `Médio` (score >= 2.5)
- `Baixo` (score < 2.5)

---

## Requisitos

- Python 3.8+ (recomendado)
- Flask

---

## Como rodar

1. Abra um terminal/PowerShell na pasta do projeto.
2. Crie e ative um ambiente virtual (opcional, mas recomendado):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

3. Instale o Flask:

```powershell
pip install flask
```

4. Execute a aplicação:

```powershell
python app.py
```

5. Abra o navegador e acesse:

```
http://127.0.0.1:5000
```

---

## Como usar

1. Escolha o **modelo** (Simples ou Ponderado).
2. Informe valores de **1 a 5** para cada impacto.
3. Clique em **Calcular**.
4. Veja o **score** e a **classificação** na tela.

---

## Estrutura do projeto

- `app.py`: código principal que roda o servidor Flask e renderiza a interface.

---
