import secrets
import tkinter as tk
from tkinter import messagebox

WORDLIST_FILE = "wordlist_ptpt.txt"


def load_wordlist(path: str = WORDLIST_FILE):
    words = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 2 and parts[0].isdigit():
                    words.append(parts[1])
    except FileNotFoundError:
        messagebox.showerror("Erro", f"Ficheiro não encontrado: {path}")
        return []

    if not words:
        messagebox.showerror("Erro", "Wordlist vazia ou mal formatada.")
        return []

    print(f"Carregadas {len(words)} palavras PT-PT memoráveis")
    return words


WORDS = load_wordlist()
SR = secrets.SystemRandom()


def diceware_index(code: str) -> int:
    idx = 0
    for d in code:
        idx = idx * 6 + (int(d) - 1)
    return idx


def gerar_passphrase_codes(n_palavras: int = 6):
    if not WORDS:
        return "", []

    frase = []
    codes = []
    for _ in range(n_palavras):
        code = "".join(str(SR.randint(1, 6)) for _ in range(5))
        idx = diceware_index(code) % len(WORDS)
        palavra = WORDS[idx]
        frase.append(palavra)
        codes.append(code)
    return " ".join(frase), codes


class DicewareGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Diceware PT-PT Seguro")
        self.root.geometry("900x390")

        # Linha 1
        top = tk.Frame(root)
        top.pack(fill="x", padx=10, pady=10)

        tk.Label(top, text="Nº palavras:").pack(side="left")
        self.entry_n = tk.Entry(top, width=4)
        self.entry_n.insert(0, "6")
        self.entry_n.pack(side="left", padx=(5, 10))

        # Capitalizar DESLIGADO por defeito
        self.var_caps = tk.BooleanVar(value=False)
        cb_caps = tk.Checkbutton(top, text="Capitalizar palavras", variable=self.var_caps)
        cb_caps.pack(side="left", padx=5)

        tk.Label(top, text="Separador:").pack(side="left", padx=(10, 2))
        self.entry_sep = tk.Entry(top, width=4)
        self.entry_sep.insert(0, " ")
        self.entry_sep.pack(side="left")

        # Linha 2
        mid = tk.Frame(root)
        mid.pack(fill="x", padx=10, pady=5)

        tk.Label(mid, text="Prefixo (ex: serviço):").pack(side="left")
        self.entry_prefix = tk.Entry(mid, width=15)
        self.entry_prefix.pack(side="left", padx=(5, 15))

        tk.Label(mid, text="Sufixo (ex: utilizador):").pack(side="left")
        self.entry_suffix = tk.Entry(mid, width=15)
        self.entry_suffix.pack(side="left", padx=(5, 15))

        tk.Label(mid, text="Dígitos/símbolos extra:").pack(side="left")
        self.entry_extra = tk.Entry(mid, width=10)
        self.entry_extra.insert(0, "")
        self.entry_extra.pack(side="left", padx=(5, 0))

        # Linha 3
        buttons = tk.Frame(root)
        buttons.pack(fill="x", padx=10, pady=5)

        self.btn_generate = tk.Button(buttons, text="Gerar passphrase", command=self.generate_and_show)
        self.btn_generate.pack(side="left")

        self.btn_copy = tk.Button(buttons, text="Copiar", command=self.copy_to_clipboard)
        self.btn_copy.pack(side="left", padx=5)

        self.btn_clear = tk.Button(buttons, text="Limpar", command=self.clear_output)
        self.btn_clear.pack(side="left", padx=5)

        self.btn_reseed = tk.Button(buttons, text="Novo RNG seed", command=self.reseed_rng)
        self.btn_reseed.pack(side="left", padx=15)

        self.var_audit = tk.BooleanVar(value=False)
        cb_audit = tk.Checkbutton(buttons, text="Mostrar códigos (audit)", variable=self.var_audit)
        cb_audit.pack(side="left", padx=5)

        # Modo temporário LIGADO por defeito
        self.var_temp = tk.BooleanVar(value=True)
        cb_temp = tk.Checkbutton(buttons, text="Modo temporário (seg):", variable=self.var_temp)
        cb_temp.pack(side="left", padx=(15, 2))

        self.entry_temp_secs = tk.Entry(buttons, width=4)
        self.entry_temp_secs.insert(0, "10")
        self.entry_temp_secs.pack(side="left")

        # Entropia
        info = tk.Frame(root)
        info.pack(fill="x", padx=10, pady=2)

        self.label_entropy = tk.Label(info, text="Entropia: -- bits")
        self.label_entropy.pack(side="left")

        # Output
        self.text_box = tk.Text(root, height=3, font=("Consolas", 14))
        self.text_box.pack(fill="x", padx=10, pady=(0, 10))

        self.audit_box = tk.Text(root, height=2, font=("Consolas", 10))
        self.audit_box.pack(fill="x", padx=10, pady=(0, 10))

        self.current_timer_id = None

    def build_final_passphrase(self, base: str) -> str:
        prefix = self.entry_prefix.get().strip()
        suffix = self.entry_suffix.get().strip()
        extra = self.entry_extra.get().strip()

        parts = []
        if prefix:
            parts.append(prefix)
        parts.append(base)
        if suffix:
            parts.append(suffix)
        final = " ".join(parts)
        if extra:
            final = final + extra
        return final

    def update_entropy_label(self, n_palavras: int):
        import math
        if not WORDS:
            self.label_entropy.config(text="Entropia: -- bits")
            return
        bits_word = math.log2(len(WORDS))
        total = bits_word * n_palavras
        self.label_entropy.config(text=f"Entropia ~ {total:.1f} bits ({bits_word:.2f} / palavra)")

    def clear_after_timeout(self):
        self.text_box.delete("1.0", tk.END)
        self.audit_box.delete("1.0", tk.END)
        self.label_entropy.config(text="Entropia: -- bits")
        self.current_timer_id = None

    def generate_and_show(self):
        if not WORDS:
            messagebox.showerror("Erro", "Wordlist não carregada.")
            return

        try:
            n = int(self.entry_n.get() or "6")
        except ValueError:
            messagebox.showerror("Erro", "Número de palavras inválido.")
            return
        if n <= 0 or n > 20:
            messagebox.showerror("Erro", "Nº de palavras deve estar entre 1 e 20.")
            return

        sep = self.entry_sep.get() or " "

        base, codes = gerar_passphrase_codes(n)
        if self.var_caps.get():
            base = sep.join(w.capitalize() for w in base.split(sep))

        final = self.build_final_passphrase(base)

        if self.current_timer_id is not None:
            self.root.after_cancel(self.current_timer_id)
            self.current_timer_id = None

        self.text_box.delete("1.0", tk.END)
        self.text_box.insert(tk.END, final)

        self.update_entropy_label(n)

        self.audit_box.delete("1.0", tk.END)
        if self.var_audit.get():
            self.audit_box.insert(tk.END, "Códigos dos dados: " + " ".join(codes))

        if self.var_temp.get():
            try:
                secs = int(self.entry_temp_secs.get() or "10")
            except ValueError:
                secs = 10
            if secs > 0:
                self.current_timer_id = self.root.after(secs * 1000, self.clear_after_timeout)

    def copy_to_clipboard(self):
        text = self.text_box.get("1.0", tk.END).strip()
        if not text:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.root.update()
        messagebox.showinfo("Copiado", "Passphrase copiada para a área de transferência.")

    def clear_output(self):
        if self.current_timer_id is not None:
            self.root.after_cancel(self.current_timer_id)
            self.current_timer_id = None
        self.text_box.delete("1.0", tk.END)
        self.audit_box.delete("1.0", tk.END)
        self.label_entropy.config(text="Entropia: -- bits")

    def reseed_rng(self):
        global SR
        SR = secrets.SystemRandom()
        messagebox.showinfo("RNG", "Novo gerador criptográfico inicializado.")


if __name__ == "__main__":
    root = tk.Tk()
    app = DicewareGUI(root)
    root.mainloop()