from datetime import datetime
import hmac
import os

from dotenv import load_dotenv
from flask import Flask, render_template, request, send_file, redirect, url_for, session
from werkzeug.security import check_password_hash

from scanner import analyse_site, generate_pdf


load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")

if not all((SECRET_KEY, ADMIN_USERNAME, ADMIN_PASSWORD_HASH)):
    raise RuntimeError(
        "Configuration incomplète : vérifiez SECRET_KEY, "
        "ADMIN_USERNAME et ADMIN_PASSWORD_HASH."
    )


app = Flask(__name__)

app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    ),
)

last_report = {}

@app.route("/", methods=["GET", "POST"])
def index():
    global last_report

    if request.method == "POST":
        url = request.form.get("url", "")
        last_report = analyse_site(url)
        last_report["timestamp"] = datetime.now().strftime("%d/%m/%Y %H:%M")
        return render_template("index.html", result=last_report)

    return render_template("index.html", result=None)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        username_is_valid = hmac.compare_digest(username, ADMIN_USERNAME)
        password_is_valid = check_password_hash(
            ADMIN_PASSWORD_HASH,
            password,
        )

        if username_is_valid and password_is_valid:
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("download_pdf"))

        return render_template(
            "login.html",
            error="Identifiants invalides",
        ), 401

    return render_template("login.html")


@app.route("/rapport_securite.pdf")
def download_pdf():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    if not last_report:
        return "Aucun rapport disponible", 404

    generate_pdf(last_report)
    return send_file("rapport-securite.pdf", as_attachment=True)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run()
