# Cybersecurity Toolkit
Ferramentas de cybersecurity para portefólio e SOC operations.
 
## Projetos
 
- **[password-leak-checker](password-leak-checker/)**  
  Verifica passwords contra HIBP dataset local (CLI + Streamlit GUI).
 
- **[password-strenght-checker](password-strenght-checker/)**  
  Análise de força de passwords com entropia de Shannon — score em bits, estimativa de tempo de cracking e sugestões de melhoria.
 
- **[CVSS-calculator](CVSS-calculator/)**  
  Calculadora CVSS v3.1 completa com scores Base, Temporal e Ambiental, tooltips explicativos por vetor e vector string em tempo real.
 
- **[diceware-ptpt](diceware-ptpt/)**  
  Gerador Diceware com GUI Tkinter.
 
- **[Severity-Calculator](Severity-Calculator/)**  
  Calculadora simples de severidade para findings de segurança.

- **[Phishing Email Analyzer](phishing-email-analyzer/)** — Ferramenta de análise de emails de phishing com extração de IoCs, análise de HTML, deteção de anexos suspeitos, integração com Abuse.ch e VirusTotal.
 
## Setup
 
```bash
git clone https://github.com/hypes999/cybersecurity-toolkit.git
cd cybersecurity-toolkit/<ferramenta>
# Segue README da pasta
```
 
## Stack
Python 3.10+, Flask, Streamlit, standard lib.
 
## Licença
MIT.
