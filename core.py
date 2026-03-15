import hashlib
from typing import Optional, Dict, Any
from storage import HashStorage

def calculate_sha1(password: str) -> str:
    """Calcula o SHA-1 da password em UTF-8, retorna hexadecimal em maiúsculas."""
    return hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

class BreachChecker:
    """Lógica principal para verificar se uma password foi vazada."""
    
    def __init__(self, hash_file_path: str):
        self.storage = HashStorage(hash_file_path)

    def check_password(self, password: str) -> Dict[str, Any]:
        """Verifica a password e retorna um dicionário com os resultados."""
        target_hash = calculate_sha1(password)
        found, count = self.storage.lookup(target_hash)
        
        return {
            "found": found,
            "hash": target_hash,
            "count": count,
            "hash_file": self.storage.file_path
        }
