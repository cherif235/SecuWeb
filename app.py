from flask import Flask, render_template, request, send_file, redirect, url_for, session
from datetime import datetime
from scanner import analyse_site, generate_pdf
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "monsecretdev")

last_report = {}

# ───── Page d’accueil libre ─────
@app.route("/", methods=["GET", "POST"])
def index():
    global last_report
    if request.method == "POST":
        url = request.form["url"]
        last_report = analyse_site(url)
        last_report["timestamp"] = datetime.now().strftime("%d/%m/%Y %H:%M")
        return render_template("index.html", result=last_report)
    return render_template("index.html", result=None)

# ───── Page de connexion ─────
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username == "admin" and password == "secu123":
            session["logged_in"] = True
            return redirect(url_for("download_pdf"))
        else:
            return render_template("login.html", error="Identifiants invalides")
    return render_template("login.html")

# ───── Téléchargement PDF sécurisé ─────
@app.route("/rapport_securite.pdf")
def download_pdf():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    if not last_report:
        return "Aucun rapport disponible", 404
    generate_pdf(last_report)
    return send_file("rapport-securite.pdf", as_attachment=True)

# ───── Déconnexion ─────
@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("index"))

# ───── Lancement local ─────
if __name__ == "__main__":
    app.run(debug=True)
