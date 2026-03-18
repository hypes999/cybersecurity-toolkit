
# Verificador de Força de Password Baseado em Entropia

Esta é uma ferramenta web para análise de força de passwords que utiliza a **entropia de Shannon** como métrica principal. A aplicação fornece feedback em tempo real sobre a força de uma password, o tempo estimado para a quebrar e sugestões concretas para a melhorar.

O projeto é construído com Python (Flask) no backend e HTML/CSS/JavaScript puros no frontend, sem dependências externas além do Flask.

![Screenshot da aplicação](screenshot.png) <!-- Adicione um screenshot aqui se desejar -->

## Funcionalidades

- **Cálculo de Entropia em Tempo Real**: A força é medida em bits de entropia, calculado no browser à medida que o utilizador digita.
- **Deteção Automática de Alfabeto**: Identifica automaticamente os conjuntos de caracteres (minúsculas, maiúsculas, dígitos, símbolos) para um cálculo preciso de `N`.
- **Estimativa de Tempo de Cracking**: Calcula o tempo teórico que um atacante levaria para forçar a password, assumindo uma capacidade de 10 mil milhões de tentativas por segundo.
- **Classificação Clara**: Categoriza a password como "Muito Fraca", "Fraca", "Razoável", "Forte" ou "Muito Forte", com um código de cores visual.
- **Sugestões de Melhoria Inteligentes**: Analisa as fraquezas da password e oferece conselhos específicos, explicando o impacto de cada mudança em termos de entropia.
- **Segurança em Primeiro Lugar**: A password **nunca** é enviada para o servidor para análise em tempo real. Todo o cálculo é feito no lado do cliente (JavaScript) para garantir que a password não transita desnecessariamente pela rede.

---

## A Metodologia: Entropia de Shannon

Muitos verificadores de força de password usam regras simplistas, como "deve conter uma maiúscula, um número e um símbolo". Esta abordagem é falha porque não mede a verdadeira imprevisibilidade. Uma password como `P@ssword1` cumpre essas regras, mas é fraca e previsível.

A entropia, por outro lado, mede a incerteza ou a desordem num sistema. No contexto de passwords, mede quão imprevisível ela é. A fórmula de Shannon é:

`H = L × log₂(N)`

Onde:
- `H` é a **Entropia** em bits. Cada bit de entropia duplica a dificuldade de adivinhar a password.
- `L` é o **comprimento** (length) da password.
- `N` é o **tamanho do conjunto de caracteres** (o "alfabeto") a partir do qual a password foi criada.

### Exemplo Concreto

- **Password A**: `senha123`
  - `L = 8`
  - `N = 26` (minúsculas) + `10` (dígitos) = `36`
  - `H = 8 × log₂(36) ≈ 8 × 5.17 = **41.36 bits**`

- **Password B**: `Gato#Frio#Sol`
  - `L = 13`
  - `N = 52` (minúsculas + maiúsculas) + `1` (símbolo `#`) -> A ferramenta assume `95` por simplicidade e segurança.
  - `H = 13 × log₂(95) ≈ 13 × 6.57 = **85.41 bits**`

A Password B, apesar de ser uma frase-passe simples, tem uma entropia exponencialmente maior e é muito mais segura.

### Tabela de Classificação

A classificação da força é baseada diretamente na entropia calculada:

| Entropia (bits) | Classificação | Cor Visual     |
|-----------------|---------------|----------------|
| < 28 bits       | Muito Fraca   | Vermelho       |
| 28–35 bits      | Fraca         | Laranja        |
| 36–59 bits      | Razoável      | Amarelo        |
| 60–127 bits     | Forte         | Verde          |
| ≥ 128 bits      | Muito Forte   | Azul-turquesa  |

---

## Decisões Técnicas

1.  **Cálculo no Frontend**: A decisão de realizar todos os cálculos de análise em tempo real no JavaScript do cliente é uma medida de segurança fundamental. Isso impede que a password do utilizador seja enviada através da Internet para um servidor, minimizando a exposição a ataques *man-in-the-middle* ou a logs de servidor acidentais. O endpoint `/analyze` no backend Flask existe como uma validação secundária opcional e demonstra como a lógica pode ser implementada no servidor, mas não é usado para o feedback instantâneo.

2.  **Simplificação do Alfabeto de Símbolos (N=95)**: Para simplificar a deteção do conjunto de caracteres, se qualquer símbolo for detetado, o tamanho do alfabeto `N` é automaticamente definido como 95. Este número representa o conjunto de caracteres ASCII imprimíveis, que é uma estimativa segura e abrangente para passwords que incluem símbolos comuns.

3.  **Sem Frameworks Frontend**: O uso de JavaScript, HTML e CSS puros demonstra a implementação dos algoritmos e da lógica de UI a partir do zero, tornando o código mais transparente e com menos dependências.

---

## Como Instalar e Executar

Para executar esta aplicação localmente, siga os passos abaixo.

### Pré-requisitos

- Python 3.6 ou superior
- `pip` (gestor de pacotes do Python)

### Passos de Instalação

1.  **Clone o repositório (ou crie os ficheiros manualmente):**

    ```bash
    git clone https://github.com/seu-usuario/password-strength-checker.git
    cd password-strength-checker
    ```

2.  **Crie e ative um ambiente virtual (recomendado):**

    ```bash
    # Para macOS/Linux
    python3 -m venv venv
    source venv/bin/activate

    # Para Windows
    python -m venv venv
    .\venv\Scripts\activate
    ```

3.  **Instale as dependências:**

    A única dependência é o Flask.

    ```bash
    pip install Flask
    ```

### Executar a Aplicação

Com o ambiente virtual ativado e as dependências instaladas, inicie o servidor Flask:

```bash
python app.py
```

O servidor será iniciado em modo de depuração.

Abra o seu browser e navegue para:

[http://127.0.0.1:5000](http://127.0.0.1:5000)

A ferramenta estará pronta a usar!
