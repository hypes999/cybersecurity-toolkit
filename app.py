import argparse
import sys
import getpass
from core import BreachChecker
from report import format_text_output, format_json_output

def main():
    parser = argparse.ArgumentParser(
        description="Verificador de vazamento de passwords (offline)",
        epilog="Exemplo: python app.py --hash-file hashes.txt"
    )
    
    parser.add_argument(
        "--hash-file", 
        required=True, 
        help="Caminho para o ficheiro de hashes SHA-1 (ordenado)."
    )
    
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument(
        "--password", 
        help="Password a verificar (menos seguro, aparece no histórico do terminal)."
    )
    input_group.add_argument(
        "--stdin", 
        action="store_true", 
        help="Lê a password (ou várias passwords, uma por linha) de stdin."
    )
    
    parser.add_argument(
        "--json", 
        action="store_true", 
        help="Gera output em formato JSON."
    )
    parser.add_argument(
        "--show-hash", 
        action="store_true", 
        help="Mostra o hash SHA-1 da password no output."
    )

    args = parser.parse_args()

    try:
        checker = BreachChecker(args.hash_file)
    except FileNotFoundError as e:
        print(f"Erro: {e}", file=sys.stderr)
        sys.exit(1)

    passwords = []
    
    if args.password:
        passwords.append(args.password)
    elif args.stdin:
        # Lê todas as linhas de stdin
        for line in sys.stdin:
            line = line.strip()
            if line:
                passwords.append(line)
    else:
        # Modo interativo com getpass
        try:
            pw = getpass.getpass("Insira a password para verificar: ")
            if pw:
                passwords.append(pw)
        except EOFError:
            pass

    if not passwords:
        print("Aviso: Nenhuma password fornecida para verificação.", file=sys.stderr)
        sys.exit(0)

    results = []
    for pw in passwords:
        res = checker.check_password(pw)
        results.append(res)
        
        if not args.json:
            # Output texto imediato
            print("-" * 30)
            print(format_text_output(res, show_hash=args.show_hash))
            
    if args.json:
        if len(results) == 1:
            print(format_json_output(results[0]))
        else:
            import json
            print(json.dumps(results, indent=4))

if __name__ == "__main__":
    main()
