# Diceware PT‑PT Seguro

Aplicação para gerar passphrases fortes em Português de Portugal, pensada para uso em cibersegurança (passwords mestres, seed phrases, etc.).  
Baseia‑se em Diceware e numa wordlist PT‑PT filtrada para palavras simples e memorizáveis.

<img width="1134" height="377" alt="diceware em funcionamento" src="https://github.com/user-attachments/assets/0193d12e-6ae3-44b8-9438-e10ab172bf94" />

## Wordlist

A wordlist `wordlist_ptpt.txt` é gerada a partir de `pt_PT.dic` com estes filtros:

- Apenas substantivos e adjetivos.  
- Comprimento entre 3 e 8 letras.  
- Sem marcas `ORIG` (estrangeirismos) nem `SEMsigla` (siglas).  

O objetivo é equilibrar segurança e facilidade de leitura/ditado.

## app_gui.py

Aplicação Tkinter que:

- Carrega a wordlist a partir de `wordlist_ptpt.txt`.  
- Gera os índices Diceware com `secrets.SystemRandom` (CSPRNG).  
- Constrói a frase final de acordo com as opções da interface gráfica.

## Funcionalidades

- Número configurável de palavras (1 a 20).  
- Separador configurável.  
- Prefixo (exemplo: serviço).  
- Sufixo (exemplo: utilizador).  
- Dígitos/símbolos extra opcionais no fim.  
- Cálculo da entropia aproximada (bits por palavra e bits totais).  
- Modo audit: mostra os códigos dos dados usados para cada palavra.  
- Modo temporário: limpa automaticamente a passphrase ao fim de X segundos.  
- Botões para gerar, copiar, limpar e reinicializar o RNG.

## Requisitos

- Python 3.10 ou superior.  
- Tkinter (incluído na maior parte das instalações de Python em Windows e macOS).

Na mesma pasta devem estar:

- `app.py`  
- `wordlist.txt`

## Instalação

1. Clona o repositório.  
2. Entra na pasta do projeto.  
3. Executa:

   `python app.py`

Em Windows podes também dar duplo clique em `app.py` se o Python estiver associado a ficheiros `.py`.

## Utilização

1. Abre o `app.py`.  
2. Define:
   - Número de palavras (por exemplo, 6 a 8 para uma password mestra).  
   - Separador entre palavras.  
   - Opcional: prefixo, sufixo e dígitos/símbolos extra.  
3. Carrega em **“Gerar passphrase”**.  
4. Se quiseres, usa **“Copiar”** para enviar a frase para o clipboard.  
5. Com o modo temporário ativo, o texto é limpo automaticamente ao fim do número de segundos configurado.

## Exemplo

Configuração:

- Nº palavras: 6  
- Separador: espaço  
- Prefixo: `email`  
- Sufixo: `utilizador123`  
- Dígitos/símbolos extra: `!`  

Exemplo de saída:

`email preto hortelão circuito morcegão furtivo assaz utilizador123!`

As palavras mudam em cada geração; o exemplo serve apenas para ilustração.

## Segurança

### Aleatoriedade

A aplicação usa `secrets.SystemRandom()`, que recorre ao gerador criptográfico do sistema operativo, adequado para geração de chaves e passwords.

### Entropia

Cada palavra adiciona aproximadamente `log2(N)` bits, onde `N` é o tamanho da wordlist.  
Com cerca de 6–7 mil palavras:

- Cada palavra dá cerca de 12–13 bits.  
- 6 palavras fornecem aproximadamente 75–80 bits de entropia, suficiente para passwords de longa duração.

### Wordlist

A lista foi desenhada para ser:

- Em Português de Portugal.  
- Relativamente simples de ler e escrever.  
- Livre de muitos termos técnicos, siglas e estrangeirismos.

### Privacidade

A aplicação não envia nem guarda passphrases.  
O backup e armazenamento seguro ficam a cargo do utilizador (por exemplo, num password manager).

## Limitações

A segurança depende de:

- Usar passphrases com palavras suficientes (recomendado 6 ou mais).  
- Não reutilizar a mesma frase em vários serviços críticos.  
- Manter o código e a wordlist livres de alterações maliciosas.

O modo audit, se ativado, mostra informação extra (códigos dos dados).  
Essa informação não deve ser capturada em screenshots ou logs em ambientes sensíveis.

## Ideias futuras

- Versão CLI (sem interface gráfica) para usar em scripts ou servidores.  
- Export direto para formatos de password managers (KeePass, Bitwarden, etc.).  
- Grelha Diceware visual para utilização com dados físicos.

Contribuições (melhorias na wordlist, UI ou documentação) são bem‑vindas via issues ou pull requests.
