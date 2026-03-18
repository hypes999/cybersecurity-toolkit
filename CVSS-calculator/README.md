# Calculadora CVSS v3.1 Interativa

Esta é uma aplicação web para calcular scores de vulnerabilidades utilizando o **Common Vulnerability Scoring System (CVSS) versão 3.1**. A ferramenta é totalmente interativa, com cálculos em tempo real, e foi construída com Python/Flask no backend e JavaScript puro no frontend, sem dependências externas além do Flask.

## O que é o CVSS e para que serve?

O CVSS é um padrão aberto da indústria para avaliar a severidade de vulnerabilidades de segurança em sistemas de computador. Ele fornece uma maneira de capturar as principais características de uma vulnerabilidade e produzir uma pontuação numérica que reflete sua gravidade. Essa pontuação pode ser usada por organizações para priorizar a remediação de vulnerabilidades e gerenciar riscos de segurança de forma eficaz.

## As 3 Métricas do CVSS

A calculadora implementa as três métricas do CVSS v3.1:

1.  **Base Score (Pontuação Base):** Representa as qualidades intrínsecas de uma vulnerabilidade que são constantes ao longo do tempo e em diferentes ambientes de usuário. Esta é a métrica mais importante e obrigatória.
2.  **Temporal Score (Pontuação Temporal):** Ajusta a pontuação base com base em fatores que mudam ao longo do tempo, como a disponibilidade de um exploit ou a existência de uma correção. É útil para entender a urgência da correção.
3.  **Environmental Score (Pontuação Ambiental):** Ajusta a pontuação base e temporal para o contexto específico de uma organização, considerando fatores como a importância do ativo afetado e controles de segurança existentes. É crucial para uma avaliação de risco precisa.

## Tabela de Classificação

As pontuações são classificadas de acordo com a seguinte tabela:

| Classificação | Pontuação   | Cor do Risco      |
|---------------|-------------|-------------------|
| **None**      | 0.0         | Cinza (`#7a8288`)   |
| **Low**       | 0.1 – 3.9   | Amarelo (`#f8c00c`) |
| **Medium**    | 4.0 – 6.9   | Laranja (`#fca800`) |
| **High**      | 7.0 – 8.9   | Vermelho (`#f04438`)|
| **Critical**  | 9.0 – 10.0  | Vermelho Escuro (`#c42115`)|

## A Vector String

A "Vector String" é uma representação textual e compacta de todos os valores selecionados na calculadora. Ela começa com `CVSS:3.1` e lista pares de `Métrica:Valor`.

**Exemplo:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

-   **Interpretação:** Esta string representa uma vulnerabilidade crítica que pode ser explorada remotamente (`AV:N`), com baixa complexidade (`AC:L`), sem necessidade de privilégios (`PR:N`) ou interação do usuário (`UI:N`). O escopo não muda (`S:U`), mas o impacto na confidencialidade (`C:H`), integridade (`I:H`) e disponibilidade (`A:H`) é alto.

-   **Funcionalidades:**
    -   A string é gerada em tempo real na calculadora.
    -   Você pode colar uma string existente no campo de input para preencher a calculadora automaticamente.
    -   Um botão "Copiar" permite transferir a string para a área de transferência.

## Casos de Uso Reais

-   **Relatórios de Pentest:** Profissionais de segurança usam o CVSS para comunicar a gravidade das falhas encontradas de forma padronizada.
-   **Gestão de Vulnerabilidades:** Equipes de TI e segurança usam as pontuações para priorizar quais vulnerabilidades corrigir primeiro, focando nos riscos mais altos.
-   **Compliance e Regulamentação:** Frameworks como **NIS2** e normas como a **ISO/IEC 27001** exigem uma gestão de riscos de segurança, e o CVSS é uma ferramenta fundamental nesse processo para avaliar e documentar a severidade das vulnerabilidades.

## Instalação e Execução

### Pré-requisitos

-   Python 3.x
-   Flask

### Passos

1.  **Clone o repositório (ou descompacte os arquivos):**

    ```bash
    # Exemplo com git
    git clone <url-do-repositorio>
    cd cvss-calculator
    ```

2.  **Instale o Flask:**

    ```bash
    pip install Flask
    ```

3.  **Execute a aplicação:**

    ```bash
    python app.py
    ```

4.  **Acesse no navegador:**

    Abra seu navegador e acesse `http://127.0.0.1:5000`.

## Descrição da Interface

A interface da calculadora é dividida em duas partes principais:

-   **Painel de Cálculo (à esquerda):** Contém as três seções (Base, Temporal, Ambiental) que podem ser expandidas ou recolhidas. Cada métrica é um grupo de botões. Ao passar o mouse sobre uma métrica, um tooltip aparece com a descrição completa, o que ela mede e exemplos de cada valor.

-   **Painel de Resultados (à direita):** Fica sempre visível e mostra em tempo real:
    -   A pontuação numérica (Base, Temporal e Ambiental).
    -   A classificação de severidade (None, Low, Medium, High, Critical).
    -   Uma barra de progresso colorida que representa visualmente o nível de risco.
    -   A Vector String completa, com um botão para copiar.
