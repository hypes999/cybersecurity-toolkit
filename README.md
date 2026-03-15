# Password Leak Checker (Offline)

Esta ferramenta permite verificar se as suas passwords foram expostas em vazamentos de dados públicos, utilizando uma lista local de hashes SHA-1. A verificação é feita de forma **100% offline**, garantindo que a sua password nunca sai da sua máquina.

## Características

- **Privacidade**: A password nunca é guardada ou transmitida em texto limpo.
- **Performance**: Utiliza pesquisa binária para permitir verificações rápidas mesmo em ficheiros de hashes com vários GB.
- **Flexibilidade**: Suporta input interativo, via argumentos ou stdin.
- **Compatibilidade**: Funciona com formatos de lista de hashes simples (apenas hash) ou com contagem (`HASH:COUNT`), como os disponibilizados pelo HaveIBeenPwned.

## Requisitos

- Python 3.10 ou superior.
- Apenas bibliotecas standard (sem dependências externas).

## Instalação

Basta clonar este repositório e navegar até à pasta da ferramenta.

```bash
cd password-leak-checker
```

## Utilização

Para utilizar a ferramenta, precisa de um ficheiro de hashes SHA-1 ordenado alfabeticamente. O ficheiro de teste `sample_hashes.txt` já está incluído para validação imediata.

### 1. Interface CLI (app.py)

1. **Modo Interativo (Mais Seguro)**:
   ```bash
   python app.py --hash-file sample_hashes.txt
   ```
   Será solicitada a password de forma segura (os caracteres não aparecem no ecrã).

2. **Passar Password via Argumento**:
   ```bash
   python app.py --hash-file sample_hashes.txt --password "MinhaSenha123"
   ```
   *Nota: Este método é menos seguro pois a password pode ficar guardada no histórico do terminal.*

3. **Utilizar Stdin (Pipes)**:
   ```bash
   echo "MinhaSenha123" | python app.py --hash-file sample_hashes.txt --stdin
   ```

4. **Output em JSON e Mostrar Hash**:
   ```bash
   python app.py --hash-file sample_hashes.txt --password "admin" --json --show-hash
   ```

### 2. Interface Web (web_server.py)

Se preferir uma interface visual, pode iniciar o servidor web local (apenas biblioteca standard):

```bash
python web_server.py
```

Depois, abra o seu browser em: [http://localhost:8080](http://localhost:8080)

## Formato do Ficheiro de Hashes

O ficheiro deve conter um hash SHA-1 por linha (em hexadecimal), opcionalmente seguido de uma contagem separada por dois pontos. **O ficheiro deve estar ordenado alfabeticamente** para que a pesquisa binária funcione corretamente.

Exemplo:
```text
0000000A0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E0E
0000000B1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F1F:42
...
```

## Limitações e Avisos

- **Não é uma garantia**: Se uma password não for encontrada, isso significa apenas que ela não está no dataset fornecido. Pode ainda ter sido vazada em outros locais ou ser uma password fraca.
- **SHA-1**: O uso de SHA-1 serve apenas para compatibilidade com datasets existentes (como o HIBP). Não deve ser usado como algoritmo de hashing para armazenamento seguro de passwords em novas aplicações.
- **Segurança do Dataset**: Proteja o seu ficheiro de hashes local. Embora contenha apenas hashes, o acesso ao mesmo pode permitir ataques de força bruta offline se não estiver protegido.
