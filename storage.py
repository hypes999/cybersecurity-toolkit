import os
from typing import Optional, Tuple

class HashStorage:
    """Abstração para acesso ao ficheiro de hashes."""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Ficheiro não encontrado: {file_path}")

    def lookup(self, target_hash: str, use_binary_search: bool = True) -> Tuple[bool, Optional[int]]:
        """
        Procura o hash no ficheiro.
        Retorna (encontrado, contagem).
        """
        if use_binary_search:
            return self._binary_search(target_hash.upper())
        return self._sequential_scan(target_hash.upper())

    def _sequential_scan(self, target_hash: str) -> Tuple[bool, Optional[int]]:
        """Leitura sequencial (útil para ficheiros pequenos ou não ordenados)."""
        with open(self.file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                
                parts = line.split(':')
                current_hash = parts[0].upper()
                
                if current_hash == target_hash:
                    count = int(parts[1]) if len(parts) > 1 else None
                    return True, count
        return False, None

    def _binary_search(self, target_hash: str) -> Tuple[bool, Optional[int]]:
        """
        Pesquisa binária num ficheiro ordenado.
        Eficiente para ficheiros de vários GB.
        """
        file_size = os.path.getsize(self.file_path)
        if file_size == 0:
            return False, None

        with open(self.file_path, 'rb') as f:
            low = 0
            high = file_size

            while low < high:
                mid = (low + high) // 2
                f.seek(mid)
                
                # Sincronizar com o início da linha (exceto se estivermos no início do ficheiro)
                if mid > 0:
                    f.readline()  # Descarta o resto da linha atual para chegar ao início da próxima
                
                current_pos = f.tell()
                if current_pos >= high and mid > 0:
                    # Se passarmos do limite superior, reduzimos o high
                    high = mid
                    continue
                
                line = f.readline().decode('utf-8', errors='ignore').strip()
                if not line:
                    # Fim do ficheiro ou linha vazia inesperada
                    if current_pos >= file_size:
                        high = mid
                    else:
                        # Tentar recuar se estivermos presos
                        high = mid
                    continue

                parts = line.split(':')
                current_hash = parts[0].upper()

                if current_hash == target_hash:
                    count = int(parts[1]) if len(parts) > 1 else None
                    return True, count
                
                if current_hash < target_hash:
                    low = f.tell()
                else:
                    high = mid
                    
        return False, None
