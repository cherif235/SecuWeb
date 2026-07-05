# SecuWeb

## Présentation

SecuWeb est une application web développée en Python permettant d'effectuer une analyse automatisée de la sécurité d'un site web.

L'application réalise plusieurs contrôles de sécurité essentiels et génère automatiquement un rapport PDF détaillé afin d'aider à identifier les principales faiblesses de sécurité d'un site.

Ce projet a été réalisé dans le cadre de mon apprentissage de la cybersécurité, de la sécurité des applications web et du développement Python.

---

# Fonctionnalités

### Analyse SSL/TLS

* Vérification de la présence d'un certificat SSL
* Vérification de la validité du certificat
* Contrôle du support HTTPS

### Analyse des en-têtes HTTP

Détection des principaux en-têtes de sécurité :

* Content-Security-Policy (CSP)
* Strict-Transport-Security (HSTS)
* X-Frame-Options
* X-Content-Type-Options
* Referrer-Policy

### Analyse des cookies

Vérification des attributs :

* Secure
* HttpOnly
* SameSite

### Contrôles de sécurité

* Vérification de la redirection HTTPS
* Détection basique de vulnérabilités XSS
* Détection basique de vulnérabilités SQL Injection

### Rapport PDF

Génération automatique d'un rapport contenant :

* Informations générales du site
* Résultats des analyses
* Score global de sécurité
* Conclusion de l'audit

---

# Technologies utilisées

* Python
* Flask
* Requests
* Cryptography
* FPDF
* Matplotlib
* HTML
* CSS

---

# Objectifs du projet

Ce projet m'a permis d'approfondir plusieurs notions importantes en cybersécurité :

* Sécurité des applications Web
* SSL/TLS
* Protocoles HTTP et HTTPS
* En-têtes HTTP de sécurité
* Analyse de vulnérabilités
* Génération automatique de rapports
* Développement d'applications Flask

---

# Architecture du projet

```text
SecuWeb/
│
├── app.py
├── scanner.py
├── templates/
├── static/
├── requirements.txt
└── rapport-securite.pdf
```

---

# Installation

```bash
git clone https://github.com/cherif235/SecuWeb.git
cd SecuWeb

python -m venv venv

source venv/bin/activate

pip install -r requirements.txt

python app.py
```
# Auteur

Abakar Tahir Cherif

Licence Informatique

Passionné par les systèmes, les réseaux et la cybersécurité.
