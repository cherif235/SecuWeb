from datetime import datetime
import hmac
import json
import os
from pathlib import Path
import secrets
import time

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
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

try:
    # Vérifie la structure du hachage sans connaître le mot de passe réel.
    check_password_hash(ADMIN_PASSWORD_HASH, "__configuration_check__")
except ValueError as exc:
    raise RuntimeError(
        "ADMIN_PASSWORD_HASH est invalide : régénérez un hachage complet."
    ) from exc


app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=16 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true"
    ),
    SESSION_PERMANENT=False,
)


REPORTS_DIR = Path(app.instance_path) / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
REPORT_MAX_AGE_SECONDS = 24 * 60 * 60


def _report_paths(report_id):
    """Retourne des chemins sûrs uniquement pour un identifiant généré localement."""
    if (
        not isinstance(report_id, str)
        or len(report_id) != 32
        or any(character not in "0123456789abcdef" for character in report_id)
    ):
        return None, None

    base_name = f"report-{report_id}"
    return (
        REPORTS_DIR / f"{base_name}.json",
        REPORTS_DIR / f"{base_name}.pdf",
    )


def _remove_report(report_id):
    report_path, pdf_path = _report_paths(report_id)
    if report_path is None:
        return

    for path in (report_path, pdf_path):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            app.logger.warning("Impossible de supprimer le fichier temporaire %s", path)


def _cleanup_stale_reports():
    """Supprime les rapports temporaires abandonnés depuis plus de 24 heures."""
    cutoff = time.time() - REPORT_MAX_AGE_SECONDS
    for path in REPORTS_DIR.glob("report-*.*"):
        try:
            if path.is_file() and path.stat().st_mtime < cutoff:
                path.unlink()
        except OSError:
            app.logger.warning("Nettoyage impossible pour %s", path)


def _save_report(report):
    previous_report_id = session.get("report_id")
    if previous_report_id:
        _remove_report(previous_report_id)

    report_id = secrets.token_hex(16)
    report_path, _ = _report_paths(report_id)
    temporary_path = report_path.with_suffix(".json.tmp")
    temporary_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    temporary_path.replace(report_path)
    session["report_id"] = report_id


_cleanup_stale_reports()


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url", "")
        report = analyse_site(url)
        report["timestamp"] = datetime.now().strftime("%d/%m/%Y %H:%M")
        _save_report(report)
        return render_template("index.html", result=report)

    return render_template("index.html", result=None)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        username_is_valid = hmac.compare_digest(username, ADMIN_USERNAME)
        password_is_valid = check_password_hash(ADMIN_PASSWORD_HASH, password)

        if username_is_valid and password_is_valid:
            # Renouvelle la session tout en conservant le rapport de cet utilisateur.
            report_id = session.get("report_id")
            session.clear()
            session["logged_in"] = True
            if report_id:
                session["report_id"] = report_id
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

    report_id = session.get("report_id")
    report_path, pdf_path = _report_paths(report_id)
    if report_path is None or not report_path.is_file():
        return "Aucun rapport disponible", 404

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _remove_report(report_id)
        session.pop("report_id", None)
        abort(404, description="Rapport indisponible ou endommagé")

    generate_pdf(report, pdf_path)
    response = send_file(
        pdf_path,
        as_attachment=True,
        download_name="rapport-securite.pdf",
        mimetype="application/pdf",
    )

    # Les fichiers sont détruits lorsque Flask a terminé l'envoi.
    response.call_on_close(lambda: _remove_report(report_id))
    session.pop("report_id", None)
    return response


@app.route("/logout")
def logout():
    _remove_report(session.get("report_id"))
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run()
