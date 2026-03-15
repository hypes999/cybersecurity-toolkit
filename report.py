import json
from typing import Dict, Any

def format_text_output(result: Dict[str, Any], show_hash: bool = False) -> str:
    """Gera uma string formatada para output humano."""
    found = result["found"]
    target_hash = result["hash"]
    count = result["count"]
    
    output_lines = []
    
    if show_hash:
        output_lines.append(f"SHA-1 Hash: {target_hash}")

    if found:
        msg = "[!!!] PWNED! A password foi encontrada no dataset de leaks."
        if count is not None:
            msg += f" (Ocorrências: {count})"
        output_lines.append(msg)
        output_lines.append("Recomenda-se mudar esta password imediatamente em todos os serviços.")
    else:
        output_lines.append("[OK] NOT FOUND! A password não foi encontrada no ficheiro local.")
        output_lines.append("Aviso: Isto não garante que a password seja segura, apenas que não consta neste dataset específico.")
        
    return "\n".join(output_lines)

def format_json_output(result: Dict[str, Any]) -> str:
    """Gera uma string JSON a partir do resultado."""
    # Adicionar uma nota curta para manter compatibilidade com o requisito
    result_copy = result.copy()
    if result["found"]:
        result_copy["note"] = "Password found in the leak dataset."
    else:
        result_copy["note"] = "Password not found in this dataset."
    
    return json.dumps(result_copy, indent=4)
