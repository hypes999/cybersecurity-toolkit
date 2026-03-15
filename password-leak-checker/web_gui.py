import streamlit as st
import os
from core import BreachChecker, calculate_sha1

# Configuração da página
st.set_page_config(
    page_title="Password Leak Checker (HIBP Offline)",
    page_icon="🔐",
    layout="centered"
)

# Estilos customizados (opcional, mas ajuda na consistência)
st.markdown("""
    <style>
    .main {
        padding: 2rem;
    }
    .stButton>button {
        width: 100%;
        border-radius: 5px;
        height: 3em;
        background-color: #ff4b4b;
        color: white;
    }
    </style>
    """, unsafe_allow_html=True)

# Sidebar
st.sidebar.title("Configurações Técnicas")
default_path = os.path.join(".", "pwned", "pwnedpasswords.txt")
hash_file_path = st.sidebar.text_input(
    "Caminho do ficheiro de hashes:",
    value=default_path,
    help="Caminho para o ficheiro de hashes (ex: pwned/pwnedpasswords.txt). O ficheiro deve estar ordenado."
)

st.sidebar.markdown("---")
st.sidebar.info(
    """
    **Sobre esta ferramenta:**
    Esta aplicação verifica se a sua password foi exposta em fugas de dados conhecidas (dataset HIBP), 
    usando uma pesquisa binária num ficheiro local de 85GB.
    
    **Privacidade:**
    A verificação é feita localmente. A sua password nunca sai do seu computador.
    """
)

# Cabeçalho principal
st.title("Password Leak Checker (HIBP Offline)")
st.markdown("Verifica passwords contra dataset HIBP local de 85GB.")

# Input de password
password = st.text_input("Insira a password para verificar:", type="password", help="A sua password não será guardada nem enviada para a rede.")

# Botão de verificar
if st.button("Verificar"):
    if not password:
        st.warning("Por favor, insira uma password.")
    elif not os.path.exists(hash_file_path):
        st.error(f"Ficheiro não encontrado: {hash_file_path}. Verifique o caminho na barra lateral.")
    else:
        # Calcular hash para mostrar (debug)
        target_hash = calculate_sha1(password)
        st.info(f"SHA-1 calculado: `{target_hash}`")

        # Iniciar verificação com spinner
        with st.spinner("A pesquisar no ficheiro gigante (85GB)..."):
            try:
                checker = BreachChecker(hash_file_path)
                result = checker.check_password(password)
                
                if result["found"]:
                    st.error(f"🚨 **PWNED!** ({result['count']} ocorrências)")
                    st.markdown(
                        """
                        <div style="background-color: #ffcccc; padding: 15px; border-radius: 5px; border-left: 5px solid #ff4b4b;">
                            ⚠️ <b>Recomendação:</b> Esta password foi encontrada em fugas de dados. 
                            Deve alterá-la imediatamente em todos os serviços onde a utiliza.
                        </div>
                        """, 
                        unsafe_allow_html=True
                    )
                else:
                    st.success("✅ **OK neste dataset**")
                    st.markdown(
                        """
                        <div style="background-color: #d4edda; padding: 15px; border-radius: 5px; border-left: 5px solid #28a745;">
                            🛡️ <b>Informação:</b> Esta password não foi encontrada no ficheiro local. 
                            No entanto, isto não garante segurança absoluta; use sempre passwords fortes e únicas.
                        </div>
                        """, 
                        unsafe_allow_html=True
                    )
            except Exception as e:
                st.error(f"Erro ao processar: {e}")

# Footer
st.markdown("---")
st.caption("Baseado na API 'Have I Been Pwned' (Dataset Offline).")
