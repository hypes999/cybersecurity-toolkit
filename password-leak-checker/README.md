# Password Leak Checker (Offline)

Esta ferramenta permite verificar se as suas passwords foram expostas em vazamentos de dados públicos, utilizando uma lista local de hashes SHA-1. A verificação é feita de forma **100% offline**, garantindo que a sua password nunca sai da sua máquina.

## Características

- **Privacidade**: A password nunca é guardada ou transmitida em texto limpo.
- **Performance**: Utiliza pesquisa binária para permitir verificações rápidas mesmo em ficheiros de hashes com vários GB.
- **Flexibilidade**: Suporta input interativo, via argumentos ou stdin.
- **Compatibilidade**: Funciona com formatos de lista de hashes simples (apenas hash) ou com contagem (`HASH:COUNT`), como os disponibilizados pelo HaveIBeenPwned.
- **Web GUI**: Interface web simples para demonstração (Streamlit).

## Requisitos

- Python 3.10 ou superior.
- Para CLI/Web: apenas bibliotecas standard.
- Para Web GUI: `pip install streamlit`.

## Instalação

```bash
git clone https://github.com/hypes999/password-leak-checker.git
cd password-leak-checker
```

## Dataset de Hashes (IMPORTANTE)

**O ficheiro `sample_hashes.txt` (pequeno, incluído)** serve para testes rápidos.

Para uso real com **85+ GB do HIBP**:

1. Instala o downloader oficial:
   ```bash
   pip install haveibeenpwned-downloader
   ```

2. Descarrega o dataset completo:
   ```bash
   haveibeenpwned-downloader pwnedpasswords
   ```

3. Usa o ficheiro gerado (`pwned/v2.0.0/pwnedpasswords-sha1-ordered-by-hash-v2.0.0.txt` ou similar):
   ```bash
   python app.py --hash-file "caminho/para/pwnedpasswords.txt"
   ```

**Porquê não incluir no repo?** GitHub limita ficheiros a 100 MB. O dataset real é ~85 GB — descarregas localmente para privacidade e performance. [docs.github](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github)

## Utilização

### 1. CLI (app.py)

**Modo Interativo** (mais seguro):
```bash
python app.py --hash-file sample_hashes.txt
```

**Via argumento**:
```bash
python app.py --hash-file sample_hashes.txt --password "MinhaSenha123"
```

**Stdin**:
```bash
echo "admin" | python app.py --hash-file sample_hashes.txt --stdin
```

**JSON + hash**:
```bash
python app.py --hash-file sample_hashes.txt --password "admin" --json --show-hash
```

### 2. Web GUI (web_gui.py)

```bash
streamlit run web_gui.py --server.port 8501
```

Abre [http://localhost:8501](http://localhost:8501). Seletor de ficheiro + input password + resultado visual.

## Desenvolvimento

```
password-leak-checker/
├── app.py          # CLI principal
├── core.py         # Cálculo SHA-1
├── storage.py      # Lookup binário
├── report.py       # Formatação resultados
├── web_gui.py      # Streamlit GUI
├── sample_hashes.txt
├── README.md
└── requirements.txt  # só streamlit
```

## Limitações e Avisos

- **Não é garantia**: Ausência no dataset ≠ password segura.
- **SHA-1**: Só para compatibilidade com HIBP, não uses para novos sistemas.
- **Protege o dataset**: É sensível para ataques offline.
- **Performance**: Com 85 GB, lookup <1s graças à pesquisa binária.

## Contribuições

Issues/PRs bem-vindos! Testa com datasets HIBP e reporta performance.

***

*Projeto para portefólio cybersecurity — foco em privacidade e performance offline.*
