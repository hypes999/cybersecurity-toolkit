# Cybersecurity Toolkit

Conjunto de ferramentas simples em Python para uso em cibersegurança: geração de passphrases, pequenas análises de segurança e automação do dia a dia.

O objetivo é ter um único repositório onde concentro scripts e apps que realmente uso e que podem ser úteis para outras pessoas.

---

## Estrutura

`cybersecurity-toolkit/`
- `diceware-ptpt/`
- `security-headers-checker/` (planeado)
- `ssh-log-analyzer/` (planeado)
- `utils/`
### 1. `diceware-ptpt/`

Gerador de passphrases seguras em Português de Portugal, com GUI em Tkinter e wordlist própria.

Principais funcionalidades:

- Wordlist PT‑PT (`wordlist.txt`) derivada de `pt_PT.dic`.
- Geração de passphrases com:
  - Número de palavras configurável.
  - Separador configurável.
  - Prefixo e sufixo (serviço, utilizador, etc.).
  - Dígitos/símbolos extra opcionais.
- Cálculo de entropia aproximada (bits por palavra e bits totais).
- Modo audit: mostra os códigos dos dados usados para cada palavra.
- Modo temporário: limpa a passphrase automaticamente ao fim de X segundos.

Mais detalhes no `diceware-ptpt/README.md`.

### 2. `security-headers-checker/` (planeado)

Ferramenta para verificar cabeçalhos de segurança em sites HTTP/HTTPS, por exemplo:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`

A ideia é gerar um pequeno relatório sobre boas práticas de segurança web.

### 3. `ssh-log-analyzer/` (planeado)

Script para analisar logs SSH (por exemplo, `auth.log`) e identificar:

- tentativas de brute force,
- IPs com muitos logins falhados,
- contas alvo mais frequentes.

Pretende ser uma ferramenta simples para apoiar análise blue team.

---

## Requisitos

- Python 3.10 ou superior.
- Tkinter (para as GUIs, normalmente já incluído em Windows e macOS).

## Instalação

1. Clona o repositório.
2. Entra na pasta do projeto.
3. Dentro de cada subpasta, segue as instruções do respetivo `README.md`.

Exemplo rápido para o Diceware PT‑PT:

- Ir a `diceware-ptpt/`.
- Correr `python app.py`.

---

## Tecnologias

- Python 3
- Tkinter
- Bibliotecas standard (`secrets`, `hashlib`, etc.)

---

## Objetivo do projeto

Este repositório serve como:

- Portefólio técnico em cibersegurança.
- Conjunto de ferramentas que uso para aprender, automatizar tarefas e demonstrar boas práticas de desenvolvimento seguro.

Contribuições (issues, sugestões ou pull requests) são bem‑vindas.
