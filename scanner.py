import ipaddress
import os
from pathlib import Path
import socket
import ssl
import tempfile
from urllib.parse import urljoin, urlparse

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from fpdf import FPDF

# ───────────────────────────── Configuration ──────────────────────────────────
DEFAULT_TIMEOUT = 8
MAX_REDIRECTS = 5
USER_AGENT = "SecuWeb/2.0 - educational web security scanner"
BASE_DIR = Path(__file__).resolve().parent
LOGO_PATH = BASE_DIR / "static" / "logo.png"

# Les tests SQLi/XSS ci-dessous sont volontairement légers.
# Ils cherchent des INDICES et ne prétendent pas confirmer une vulnérabilité.
# N'utilisez SecuWeb que sur des sites que vous êtes autorisé à tester.

def _session():
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    return s


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise ValueError("URL vide")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Seuls les protocoles HTTP et HTTPS sont autorisés")
    if not parsed.hostname:
        raise ValueError("URL invalide")
    if parsed.username or parsed.password:
        raise ValueError("Les identifiants intégrés dans une URL sont interdits")

    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("Port invalide") from exc

    return url


def _validate_public_url(url: str) -> str:
    """Bloque localhost, les réseaux privés et les adresses non routables."""
    url = _normalize_url(url)
    hostname = urlparse(url).hostname

    try:
        direct_ip = ipaddress.ip_address(hostname)
        addresses = {direct_ip}
    except ValueError:
        try:
            addresses = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(hostname, None)
            }
        except socket.gaierror as exc:
            raise ValueError("Nom de domaine introuvable") from exc

    if not addresses:
        raise ValueError("Aucune adresse IP trouvée")

    blocked = [address for address in addresses if not address.is_global]
    if blocked:
        raise ValueError(
            "Adresse locale, privée ou non routable interdite par SecuWeb"
        )

    return url


def _request(url, **kwargs):
    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    kwargs.pop("allow_redirects", None)
    current_url = _normalize_url(url)

    with _session() as client:
        for redirect_count in range(MAX_REDIRECTS + 1):
            current_url = _validate_public_url(current_url)
            response = client.get(current_url, allow_redirects=False, **kwargs)

            if not (response.is_redirect or response.is_permanent_redirect):
                return response

            location = response.headers.get("Location")
            if not location:
                return response

            if redirect_count == MAX_REDIRECTS:
                raise requests.TooManyRedirects(
                    f"Plus de {MAX_REDIRECTS} redirections"
                )

            current_url = urljoin(current_url, location)
            # Les paramètres concernent uniquement la requête initiale.
            kwargs.pop("params", None)

    raise requests.TooManyRedirects("Boucle de redirection")


# ───────────────────────────── Analyse du site ────────────────────────────────
def analyse_site(url: str) -> dict:
    try:
        url = _validate_public_url(url)
    except ValueError as exc:
        return {
            "url": url,
            "final_url": None,
            "http_code": "Erreur",
            "request_error": str(exc),
            "ssl": {"valid": False, "error": str(exc)},
            "headers": header_audit({}),
            "cookies": [],
            "sql_injection": "Non testable",
            "xss": "Non testable",
            "https_redirect": False,
            "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M"),
            "score": 0,
            "score_details": {
                "SSL": 0, "HTTP": 0, "SQLi": 0, "XSS": 0, "Headers": 0
            },
        }

    resp = None
    request_error = None
    try:
        resp = _request(url)
    except (requests.RequestException, ValueError) as exc:
        request_error = f"{type(exc).__name__}: {exc}"

    report = {
        "url": url,
        "final_url": resp.url if resp is not None else None,
        "http_code": resp.status_code if resp is not None else "Erreur",
        "request_error": request_error,
        "ssl": check_ssl(url),
        "headers": header_audit(resp.headers if resp is not None else {}),
        "cookies": cookie_audit(resp.cookies if resp is not None else []),
        "sql_injection": sql_test(url),
        "xss": xss_test(url),
        "https_redirect": https_redirect(url),
        "timestamp": datetime.now().strftime("%d/%m/%Y %H:%M"),
    }
    report["score"], report["score_details"] = compute_score(report)
    return report


# ───────────────────────────── Contrôles techniques ───────────────────────────
def check_ssl(url):
    try:
        url = _validate_public_url(url)
        host = urlparse(url).hostname
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                cert_bin = tls_sock.getpeercert(binary_form=True)
                tls_version = tls_sock.version()

        cert = x509.load_der_x509_certificate(cert_bin, default_backend())

        if hasattr(cert, "not_valid_after_utc"):
            expiry = cert.not_valid_after_utc
        else:
            expiry = cert.not_valid_after.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        days = (expiry - now).days

        return {
            "valid": days >= 0,
            "expire_in_days": days,
            "tls_version": tls_version,
            "issuer": cert.issuer.rfc4514_string(),
            "subject": cert.subject.rfc4514_string(),
        }
    except Exception as exc:
        return {"valid": False, "error": f"{type(exc).__name__}: {exc}"}


def header_audit(headers):
    wanted = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ]
    # requests utilise normalement CaseInsensitiveDict, mais on normalise aussi
    # pour rendre la fonction fiable avec un dictionnaire classique.
    normalized = {str(k).lower(): v for k, v in dict(headers).items()}
    return {name: name.lower() in normalized for name in wanted}


def cookie_audit(cookies):
    """
    Analyse prudente des attributs visibles dans le CookieJar de requests.

    Important : requests ne conserve pas toujours tous les attributs Set-Cookie
    de façon uniforme. Lorsqu'un attribut ne peut pas être établi avec
    suffisamment de certitude, SecuWeb retourne "Non déterminé" plutôt que False.
    """
    out = []

    for cookie in cookies:
        rest = getattr(cookie, "_rest", {}) or {}
        rest_lower = {str(k).lower(): v for k, v in rest.items()}

        # Secure est un attribut natif de Cookie dans http.cookiejar.
        secure = bool(cookie.secure)

        # HttpOnly peut apparaître dans _rest sous différentes formes.
        if "httponly" in rest_lower:
            httponly = True
        else:
            httponly = "Non déterminé"

        # SameSite n'est pas garanti dans CookieJar.
        samesite = rest_lower.get("samesite")
        if samesite in (None, ""):
            samesite = "Non déterminé"

        out.append({
            "name": cookie.name,
            "Secure": secure,
            "HttpOnly": httponly,
            "SameSite": samesite,
        })

    return out


SQL_ERROR_MARKERS = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysqli_sql_exception",
    "mysql_fetch",
    "postgresql query failed",
    "pg_query(",
    "sqlite3.operationalerror",
    "sqlite error",
    "ora-01756",
    "ora-00933",
    "sqlstate[",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
)


def sql_test(url):
    """
    Test heuristique et non destructif :
    compare une réponse normale à une requête contenant une apostrophe.
    Le résultat 'Indice détecté' n'est PAS une confirmation de SQL injection.
    """
    try:
        baseline = _request(url, params={"q": "secuweb_test"})
        probe = _request(url, params={"q": "secuweb_test'"})

        baseline_text = baseline.text.lower()[:500_000]
        probe_text = probe.text.lower()[:500_000]

        new_markers = [
            marker for marker in SQL_ERROR_MARKERS
            if marker in probe_text and marker not in baseline_text
        ]

        if new_markers:
            return "Indice détecté"
        return "Aucun indice détecté"
    except (requests.RequestException, ValueError):
        return "Non testable"


def xss_test(url):
    """
    Test de réflexion uniquement.
    Une chaîne réfléchie dans la réponse n'est pas, à elle seule,
    la preuve d'une vulnérabilité XSS exploitable.
    """
    marker = "SECUWEB_XSS_7f3a9"
    try:
        response = _request(url, params={"secuweb_xss": marker})
        if marker in response.text:
            return "Entrée réfléchie à vérifier"
        return "Aucun indice détecté"
    except (requests.RequestException, ValueError):
        return "Non testable"


def https_redirect(url):
    host = urlparse(url).hostname
    if not host:
        return False
    try:
        response = _request(f"http://{host}")
        return response.url.lower().startswith("https://")
    except (requests.RequestException, ValueError):
        return False


# ───────────────────────────── Calcul du score ────────────────────────────────
def compute_score(report):
    """
    Calcule un indice SecuWeb, pas une note de sécurité absolue.

    Chaque contrôle disponible contribue à l'indice. Un contrôle "Non testable"
    est exclu du dénominateur au lieu d'être assimilé à une vulnérabilité.
    Le dictionnaire score_details conserve None pour ces contrôles.
    """
    details = {}

    ssl_info = report.get("ssl", {})
    ssl_score = 0
    if ssl_info.get("valid"):
        ssl_score = 20
        days = ssl_info.get("expire_in_days")
        if isinstance(days, int) and days < 30:
            ssl_score = 15
    details["SSL"] = ssl_score

    http_code = report.get("http_code")
    if isinstance(http_code, int):
        http_score = 10 if 200 <= http_code < 400 else 0
        final_url = report.get("final_url") or ""
        if final_url.lower().startswith("https://"):
            http_score += 5
        if report.get("https_redirect"):
            http_score += 5
        details["HTTP/HTTPS"] = min(http_score, 20)
    else:
        details["HTTP/HTTPS"] = None

    sql_status = report.get("sql_injection")
    if sql_status == "Aucun indice détecté":
        details["SQLi"] = 20
    elif sql_status == "Indice détecté":
        details["SQLi"] = 0
    else:
        details["SQLi"] = None

    xss_status = report.get("xss")
    if xss_status == "Aucun indice détecté":
        details["XSS"] = 20
    elif xss_status in {
        "Réflexion détectée",
        "Entrée réfléchie à vérifier",
    }:
        # Une réflexion n'est pas une faille XSS confirmée. Elle reçoit un
        # score intermédiaire en attendant une vérification manuelle.
        details["XSS"] = 10
    else:
        details["XSS"] = None

    headers = report.get("headers", {})
    if headers:
        details["En-têtes"] = min(
            sum(4 for present in headers.values() if present), 20
        )
    else:
        details["En-têtes"] = None

    available = [v for v in details.values() if isinstance(v, (int, float))]
    if not available:
        return 0, details

    score = round(sum(available) / (20 * len(available)) * 100)
    return score, details


# ────────────────────────────── Génération PDF ────────────────────────────────
BRAND_NAVY = (15, 23, 42)
BRAND_BLUE = (37, 99, 235)
BRAND_CYAN = (14, 165, 233)
BRAND_LIGHT = (239, 246, 255)
TEXT_DARK = (30, 41, 59)
TEXT_MUTED = (100, 116, 139)


def _configure_pdf_fonts(pdf):
    """Utilise une police Unicode embarquée lorsqu'elle est disponible."""
    font_directories = (
        BASE_DIR / "static" / "fonts",
        Path("/usr/share/fonts/truetype/dejavu"),
    )

    for directory in font_directories:
        regular = directory / "DejaVuSans.ttf"
        bold = directory / "DejaVuSans-Bold.ttf"
        if not (regular.is_file() and bold.is_file()):
            continue

        pdf.add_font("SecuWebSans", "", str(regular))
        pdf.add_font("SecuWebSans", "B", str(bold))
        # Le fichier normal sert de repli portable pour le texte secondaire.
        pdf.add_font("SecuWebSans", "I", str(regular))
        pdf.brand_font = "SecuWebSans"
        return

    pdf.brand_font = "Helvetica"


class CustomPDF(FPDF):
    def header(self):
        # La première page possède sa propre couverture.
        if self.page_no() == 1:
            return

        self.set_fill_color(*BRAND_NAVY)
        self.rect(0, 0, self.w, 20, "F")

        if LOGO_PATH.is_file():
            self.image(str(LOGO_PATH), x=14, y=3.5, w=13, h=13)

        self.set_xy(32, 5)
        self.set_font(self.brand_font, "B", 11)
        self.set_text_color(255, 255, 255)
        self.cell(90, 8, "SECUWEB", align="L")

        self.set_xy(120, 5)
        self.set_font(self.brand_font, "", 8)
        self.set_text_color(203, 213, 225)
        self.cell(75, 8, "RAPPORT D'ANALYSE DE SÉCURITÉ", align="R")

        self.set_draw_color(*BRAND_CYAN)
        self.set_line_width(0.7)
        self.line(14, 20, self.w - 14, 20)
        self.set_y(27)

    def footer(self):
        self.set_y(-16)
        self.set_draw_color(203, 213, 225)
        self.set_line_width(0.3)
        self.line(15, self.get_y(), self.w - 15, self.get_y())

        self.set_y(-13)
        self.set_font(self.brand_font, "", 8)
        self.set_text_color(*TEXT_MUTED)
        self.cell(90, 7, "AbakarTech | SecuWeb 2.1", align="L")
        self.cell(
            90,
            7,
            f"Page {self.page_no()}/{{nb}}",
            align="R",
        )


def safe_text(value):
    return "Non disponible" if value is None else str(value)


def write_line(pdf, text, h=7):
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(
        w=pdf.epw,
        h=h,
        text=safe_text(text),
        new_x="LMARGIN",
        new_y="NEXT",
    )

def section_title(pdf, number, title):
    if pdf.get_y() > 258:
        pdf.add_page()

    pdf.ln(4)
    y = pdf.get_y()
    pdf.set_fill_color(*BRAND_LIGHT)
    pdf.rect(pdf.l_margin, y, pdf.epw, 11, "F")
    pdf.set_fill_color(*BRAND_BLUE)
    pdf.rect(pdf.l_margin, y, 3, 11, "F")
    pdf.set_xy(pdf.l_margin + 7, y + 1.5)
    pdf.set_font(pdf.brand_font, "B", 12)
    pdf.set_text_color(*BRAND_NAVY)
    pdf.cell(pdf.epw - 7, 8, f"{number}. {title}")
    pdf.set_y(y + 14)


def draw_score_bar(pdf, label, percent):
    if pdf.get_y() > 265:
        pdf.add_page()

    percent = max(0, min(100, percent))
    x_label, x_bar, max_w, h = 20, 64, 92, 6
    y = pdf.get_y() + 2
    bar_w = (percent / 100) * max_w

    if percent >= 80:
        fill = (0, 153, 76)
    elif percent >= 50:
        fill = (255, 140, 0)
    else:
        fill = (204, 0, 0)

    pdf.set_xy(x_label, y - 1)
    pdf.set_font(pdf.brand_font, "", 10)
    pdf.set_text_color(*TEXT_DARK)
    pdf.cell(40, 8, safe_text(label))

    pdf.set_fill_color(226, 232, 240)
    pdf.rect(x_bar, y, max_w, h, "F")
    pdf.set_fill_color(*fill)
    pdf.rect(x_bar, y, bar_w, h, "F")

    pdf.set_xy(x_bar + max_w + 4, y - 1)
    pdf.set_font(pdf.brand_font, "B", 9)
    pdf.cell(20, 8, f"{int(percent)}%")
    pdf.set_y(y + 10)
    pdf.set_x(pdf.l_margin)

def generate_pdf(result, output_path="rapport-securite.pdf"):
    pdf = CustomPDF()
    _configure_pdf_fonts(pdf)
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(left=15, top=28, right=15)

    # Page 1 : couverture professionnelle
    pdf.add_page()
    pdf.set_fill_color(*BRAND_NAVY)
    pdf.rect(0, 0, pdf.w, 96, "F")
    pdf.set_fill_color(*BRAND_BLUE)
    pdf.rect(0, 92, pdf.w, 4, "F")

    if LOGO_PATH.is_file():
        pdf.image(str(LOGO_PATH), x=168, y=14, w=24, h=24)

    pdf.set_xy(18, 16)
    pdf.set_font(pdf.brand_font, "B", 9)
    pdf.set_text_color(*BRAND_CYAN)
    pdf.cell(90, 7, "ABAKARTECH | CYBERSÉCURITÉ")

    pdf.set_xy(18, 34)
    pdf.set_font(pdf.brand_font, "B", 29)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(120, 13, "SECUWEB")

    pdf.set_xy(18, 51)
    pdf.set_font(pdf.brand_font, "B", 17)
    pdf.set_text_color(226, 232, 240)
    pdf.cell(175, 10, "Rapport d'analyse de sécurité Web")

    pdf.set_xy(18, 68)
    pdf.set_font(pdf.brand_font, "", 9)
    pdf.set_text_color(148, 163, 184)
    pdf.cell(
        175,
        7,
        "SSL/TLS | HTTP | En-têtes | Cookies | Indices SQLi et XSS",
    )

    ts = result.get("timestamp") or datetime.now().strftime("%d/%m/%Y %H:%M")
    score = result.get("score", 0)
    if score >= 80:
        score_color = (0, 153, 76)
        score_label = "Niveau observé : élevé"
    elif score >= 50:
        score_color = (234, 88, 12)
        score_label = "Niveau observé : intermédiaire"
    else:
        score_color = (190, 24, 93)
        score_label = "Niveau observé : à renforcer"

    # Carte d'identification de l'analyse
    pdf.set_fill_color(*BRAND_LIGHT)
    pdf.rect(15, 111, 180, 45, "F")
    pdf.set_fill_color(*BRAND_BLUE)
    pdf.rect(15, 111, 3, 45, "F")

    pdf.set_xy(24, 117)
    pdf.set_font(pdf.brand_font, "B", 9)
    pdf.set_text_color(*TEXT_MUTED)
    pdf.cell(35, 7, "SITE ANALYSÉ")
    pdf.set_xy(24, 125)
    pdf.set_font(pdf.brand_font, "B", 11)
    pdf.set_text_color(*TEXT_DARK)
    pdf.multi_cell(108, 6, safe_text(result.get("url")))

    pdf.set_xy(24, 143)
    pdf.set_font(pdf.brand_font, "", 9)
    pdf.set_text_color(*TEXT_MUTED)
    pdf.cell(105, 6, f"Analyse générée le {ts}")

    # Bloc score
    pdf.set_fill_color(*score_color)
    pdf.rect(145, 116, 40, 31, "F")
    pdf.set_xy(145, 120)
    pdf.set_font(pdf.brand_font, "B", 22)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(40, 11, f"{score}", align="C")
    pdf.set_xy(145, 133)
    pdf.set_font(pdf.brand_font, "B", 8)
    pdf.cell(40, 7, "INDICE / 100", align="C")

    pdf.set_xy(24, 169)
    pdf.set_font(pdf.brand_font, "B", 12)
    pdf.set_text_color(*score_color)
    pdf.cell(160, 8, score_label)

    pdf.set_xy(24, 184)
    pdf.set_font(pdf.brand_font, "", 10)
    pdf.set_text_color(*TEXT_MUTED)
    pdf.multi_cell(
        162,
        6,
        "Ce document synthétise des contrôles automatisés portant sur le "
        "chiffrement, la réponse HTTP, les en-têtes de sécurité, les cookies "
        "et certains indices liés aux injections SQL et XSS.",
    )

    pdf.set_xy(24, 226)
    pdf.set_font(pdf.brand_font, "I", 9)
    pdf.set_text_color(*TEXT_MUTED)
    pdf.multi_cell(
        162,
        6,
        "Analyse indicative : un résultat automatisé ne confirme ni l'absence "
        "ni la présence certaine d'une vulnérabilité.",
    )

    # Page 2 : informations générales
    pdf.add_page()
    section_title(pdf, 1, "Informations générales")

    pdf.set_font(pdf.brand_font, "", 11)
    pdf.set_text_color(*TEXT_DARK)
    write_line(pdf, f"URL : {result.get('url', 'Non disponible')}")
    write_line(pdf, f"Code HTTP : {result.get('http_code', 'Non disponible')}")

    ssl_info = result.get("ssl", {})
    ssl_valid = ssl_info.get("valid", False)
    write_line(pdf, f"Certificat SSL valide : {'Oui' if ssl_valid else 'Non'}")

    if ssl_valid:
        write_line(
            pdf,
            f"Expiration du certificat : "
            f"{ssl_info.get('expire_in_days', 'Non disponible')} jours"
        )
    elif ssl_info.get("error"):
        write_line(pdf, f"Erreur SSL : {ssl_info.get('error')}")

    write_line(
        pdf,
        "URL finale en HTTPS : "
        + (
            "Oui"
            if str(result.get("final_url") or "").lower().startswith("https://")
            else "Non"
        )
    )
    write_line(
        pdf,
        "Redirection HTTP vers HTTPS : "
        + ("Oui" if result.get("https_redirect") else "Non")
    )
    write_line(
        pdf,
        f"Test d'injection SQL : {result.get('sql_injection', 'Non testable')}"
    )
    write_line(
        pdf,
        f"Test de réflexion XSS : {result.get('xss', 'Non testable')}"
    )

    # Score
    section_title(pdf, 2, "Score de sécurité")
    pdf.set_font(pdf.brand_font, "B", 12)
    pdf.set_text_color(*TEXT_DARK)
    write_line(pdf, f"Indice SecuWeb : {score}/100")
    pdf.ln(3)
    draw_score_bar(pdf, "Global", score)

    for label, value in result.get("score_details", {}).items():
        if value is None:
            pdf.set_font(pdf.brand_font, "", 10)
            pdf.set_text_color(100, 100, 100)
            write_line(pdf, f"{label} : Non testable", 6)
        else:
            draw_score_bar(pdf, label, (value / 20) * 100)

    # Graphique
    pdf.ln(5)
    tmp_path = None
    try:
        score_items = [
            (label, value)
            for label, value in result.get("score_details", {}).items()
            if isinstance(value, (int, float))
        ]
        labels = [label for label, _ in score_items]
        values = [value for _, value in score_items]

        if labels and values:
            fig, ax = plt.subplots(figsize=(6, 3))
            bars = ax.barh(labels, values, color="#2563EB")
            ax.set_xlim(0, 20)
            ax.set_xlabel("Score / 20")
            ax.set_title("Détail des scores de sécurité")
            ax.grid(axis="x", color="#E2E8F0", linewidth=0.8)
            ax.set_axisbelow(True)
            ax.spines["top"].set_visible(False)
            ax.spines["right"].set_visible(False)

            for bar in bars:
                width = bar.get_width()
                ax.text(
                    min(width + 0.3, 19.5),
                    bar.get_y() + bar.get_height() / 2,
                    f"{int(width)}",
                    va="center",
                    fontsize=9,
                )

            plt.tight_layout()
            with tempfile.NamedTemporaryFile(delete=False, suffix=".png") as tmp:
                tmp_path = tmp.name

            fig.savefig(tmp_path, dpi=150, bbox_inches="tight")
            plt.close(fig)

            if pdf.get_y() > 190:
                pdf.add_page()

            pdf.image(tmp_path, x=30, y=pdf.get_y() + 5, w=150)
            pdf.ln(85)

    except Exception as e:
        pdf.set_text_color(180, 0, 0)
        write_line(pdf, f"Graphique non généré : {e}")
        pdf.set_text_color(*TEXT_DARK)

    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    # En-têtes
    section_title(pdf, 3, "En-têtes HTTP de sécurité")
    pdf.set_font(pdf.brand_font, "", 10)
    pdf.set_text_color(*TEXT_DARK)

    headers = result.get("headers", {})
    if not headers:
        write_line(pdf, "Aucune information disponible concernant les en-têtes.")
    else:
        for header, present in headers.items():
            status = "Présent" if present else "Absent"
            write_line(pdf, f"- {header} : {status}")

    # Cookies
    section_title(pdf, 4, "Cookies")
    pdf.set_font(pdf.brand_font, "", 10)
    pdf.set_text_color(*TEXT_DARK)

    cookies = result.get("cookies", [])
    if not cookies:
        write_line(pdf, "Aucun cookie détecté.")
    else:
        for index, cookie in enumerate(cookies, 1):
            write_line(
                pdf,
                f"Cookie {index} : {cookie.get('name', 'Sans nom')}"
            )
            pdf.set_x(pdf.l_margin + 5)
            pdf.multi_cell(
                w=pdf.epw - 5,
                h=6,
                text=(
                    f"Secure : {cookie.get('Secure', False)} | "
                    f"HttpOnly : {cookie.get('HttpOnly', 'Non déterminé')} | "
                    f"SameSite : {cookie.get('SameSite', 'Non déterminé')}"
                ),
                new_x="LMARGIN",
                new_y="NEXT",
            )
            pdf.ln(2)

    # Conclusion
    pdf.add_page()
    section_title(pdf, 5, "Conclusion")
    pdf.set_font(pdf.brand_font, "", 11)
    pdf.set_text_color(*TEXT_DARK)

    if score >= 80:
        conclusion = (
            "Les contrôles SecuWeb obtiennent un indice élevé. Les éléments "
            "observés sont majoritairement conformes aux contrôles effectués. "
            "Les protections analysées semblent correctement configurées. "
            "Une vérification périodique reste recommandée."
        )
    elif score >= 60:
        conclusion = (
            "Les contrôles SecuWeb obtiennent un indice globalement satisfaisant, "
            "mais certaines protections peuvent encore être renforcées. Les éléments "
            "signalés comme absents ou insuffisants doivent être examinés en priorité."
        )
    elif score >= 40:
        conclusion = (
            "L'indice SecuWeb est moyen. Plusieurs protections "
            "importantes sont absentes ou insuffisantes. Des mesures correctives "
            "sont recommandées afin de réduire l'exposition du site aux attaques."
        )
    else:
        conclusion = (
            "L'indice SecuWeb est faible selon les contrôles automatisés "
            "effectués. Plusieurs mesures de protection doivent être examinées et "
            "renforcées en priorité."
        )

    write_line(pdf, conclusion)

    # Recommandations
    pdf.ln(5)
    pdf.set_font(pdf.brand_font, "B", 12)
    pdf.set_text_color(*BRAND_BLUE)
    write_line(pdf, "Recommandations")

    pdf.set_font(pdf.brand_font, "", 10)
    pdf.set_text_color(*TEXT_DARK)
    recommendations = []

    if not ssl_info.get("valid"):
        recommendations.append("Configurer un certificat SSL/TLS valide.")

    if not result.get("https_redirect"):
        recommendations.append(
            "Forcer la redirection automatique de HTTP vers HTTPS."
        )

    for header, present in headers.items():
        if not present:
            recommendations.append(
                f"Configurer l'en-tête de sécurité {header}."
            )

    for cookie in cookies:
        name = cookie.get("name", "Sans nom")
        if not cookie.get("Secure"):
            recommendations.append(
                f"Vérifier et, si approprié, activer l'attribut Secure pour le cookie {name}."
            )
        if cookie.get("HttpOnly") is False:
            recommendations.append(
                f"Activer l'attribut HttpOnly pour le cookie {name}."
            )

    if result.get("sql_injection") == "Indice détecté":
        recommendations.append(
            "Un indice d'erreur SQL a été observé. Vérifier manuellement les entrées "
            "utilisateur et utiliser des requêtes paramétrées afin de réduire les "
            "risques d'injection SQL."
        )

    if result.get("xss") in {
        "Réflexion détectée",
        "Entrée réfléchie à vérifier",
    }:
        recommendations.append(
            "Une entrée réfléchie a été observée, sans confirmer une faille. "
            "Vérifier manuellement le contexte de sortie, puis valider et encoder "
            "les entrées utilisateur afin de réduire les risques de Cross-Site "
            "Scripting (XSS)."
        )

    if recommendations:
        for recommendation in recommendations:
            write_line(pdf, f"- {recommendation}", 6)
    else:
        write_line(
            pdf,
            "Aucune recommandation critique n'a été générée par les contrôles automatisés."
        )

    pdf.ln(8)
    pdf.set_font(pdf.brand_font, "B", 11)
    pdf.set_text_color(*BRAND_BLUE)
    write_line(pdf, "Analyse", 6)
    pdf.set_font(pdf.brand_font, "", 9)
    pdf.set_text_color(*TEXT_MUTED)
    write_line(
        pdf,
        "L'indice SecuWeb synthétise uniquement les contrôles exécutés par cet outil. ",
        6,
    )

    # Avertissement
    pdf.ln(8)
    pdf.set_font(pdf.brand_font, "I", 9)
    pdf.set_text_color(*TEXT_MUTED)
    write_line(
        pdf,
        "Ce rapport est généré automatiquement par SecuWeb. Les contrôles effectués "
        "constituent une analyse indicative et ne remplacent pas un audit de sécurité "
        "complet réalisé manuellement.",
        6,
    )

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(output_path))
    return str(output_path)