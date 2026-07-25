import ssl, socket, os, requests, tempfile, matplotlib.pyplot as plt
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from fpdf import FPDF

# ───────────────────────────── Configuration ──────────────────────────────────
DEFAULT_TIMEOUT = 8
USER_AGENT = "SecuWeb/2.0 - educational web security scanner"

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
    if not parsed.hostname:
        raise ValueError("URL invalide")
    return url


def _request(url, **kwargs):
    kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
    kwargs.setdefault("allow_redirects", True)
    return _session().get(url, **kwargs)


# ───────────────────────────── Analyse du site ────────────────────────────────
def analyse_site(url: str) -> dict:
    try:
        url = _normalize_url(url)
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
    except requests.RequestException as exc:
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
    host = urlparse(url).hostname
    if not host:
        return {"valid": False, "error": "Nom d'hôte invalide"}

    try:
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
    suffisamment de certitude, SecuWeb retourne "Non determine" plutôt que False.
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
            httponly = "Non determine"

        # SameSite n'est pas garanti dans CookieJar.
        samesite = rest_lower.get("samesite")
        if samesite in (None, ""):
            samesite = "Non determine"

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
    except requests.RequestException:
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
            return "Réflexion détectée"
        return "Aucun indice détecté"
    except requests.RequestException:
        return "Non testable"


def https_redirect(url):
    host = urlparse(url).hostname
    if not host:
        return False
    try:
        response = _request(f"http://{host}")
        return response.url.lower().startswith("https://")
    except requests.RequestException:
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
        if report.get("https_redirect") or final_url.lower().startswith("https://"):
            http_score += 10
        details["HTTP"] = min(http_score, 20)
    else:
        details["HTTP"] = None

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
    elif xss_status == "Réflexion détectée":
        details["XSS"] = 5
    else:
        details["XSS"] = None

    headers = report.get("headers", {})
    if headers:
        details["Headers"] = min(
            sum(4 for present in headers.values() if present), 20
        )
    else:
        details["Headers"] = None

    available = [v for v in details.values() if isinstance(v, (int, float))]
    if not available:
        return 0, details

    score = round(sum(available) / (20 * len(available)) * 100)
    return score, details


# ────────────────────────────── Génération PDF ────────────────────────────────
class CustomPDF(FPDF):
    def header(self):
        if os.path.exists("static/logo.png"):
            self.image("static/logo.png", x=175, y=5, w=20)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(110, 110, 110)
        self.cell(
            0, 10,
            f"AbakarTech - SecuWeb 2.1 | Page {self.page_no()}/{{nb}}",
            align="C",
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
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(0, 102, 204)
    write_line(pdf, f"{number}. {title}", 8)
    pdf.set_draw_color(200, 200, 200)
    pdf.set_line_width(0.3)
    y = pdf.get_y()
    pdf.line(pdf.l_margin, y, pdf.w - pdf.r_margin, y)
    pdf.ln(3)

def draw_score_bar(pdf, label, percent):
    if pdf.get_y() > 265:
        pdf.add_page()

    percent = max(0, min(100, percent))
    x_label, x_bar, max_w, h = 20, 60, 110, 6
    y = pdf.get_y() + 2
    bar_w = (percent / 100) * max_w

    if percent >= 80:
        fill = (0, 153, 76)
    elif percent >= 50:
        fill = (255, 140, 0)
    else:
        fill = (204, 0, 0)

    pdf.set_xy(x_label, y - 1)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(40, 40, 40)
    pdf.cell(35, 8, safe_text(label))

    pdf.set_fill_color(230, 230, 230)
    pdf.rect(x_bar, y, max_w, h, "F")
    pdf.set_fill_color(*fill)
    pdf.rect(x_bar, y, bar_w, h, "F")

    pdf.set_xy(x_bar + max_w + 3, y - 1)
    pdf.cell(20, 8, f"{int(percent)}%")
    pdf.set_y(y + 10)
    pdf.set_x(pdf.l_margin)

def generate_pdf(result):
    pdf = CustomPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.set_margins(left=15, top=15, right=15)

    # Page 1 : couverture
    pdf.add_page()
    pdf.ln(18)

    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(33, 53, 85)
    pdf.cell(0, 12, "ABAKARTECH", align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "B", 17)
    pdf.set_text_color(0, 102, 204)
    pdf.cell(
        0, 12, "Rapport d'analyse de securite Web",
        align="C", new_x="LMARGIN", new_y="NEXT"
    )

    pdf.set_draw_color(0, 102, 204)
    pdf.set_line_width(0.8)
    y = pdf.get_y() + 2
    pdf.line(45, y, 165, y)
    pdf.ln(15)

    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(40, 40, 40)

    ts = result.get("timestamp") or datetime.now().strftime("%d/%m/%Y %H:%M")
    write_line(pdf, f"Site analyse : {result.get('url', 'Non disponible')}")
    write_line(pdf, f"Date de l'analyse : {ts}")
    pdf.ln(8)

    score = result.get("score", 0)
    pdf.set_font("Helvetica", "B", 18)
    if score >= 80:
        pdf.set_text_color(0, 153, 76)
    elif score >= 50:
        pdf.set_text_color(255, 140, 0)
    else:
        pdf.set_text_color(204, 0, 0)

    pdf.cell(
        0, 12, f"Indice SecuWeb : {score}/100",
        align="C", new_x="LMARGIN", new_y="NEXT"
    )
    pdf.ln(5)
    draw_score_bar(pdf, "Indice SecuWeb", score)
    pdf.ln(10)

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(70, 70, 70)
    write_line(
        pdf,
        "Ce rapport presente des controles automatises de plusieurs elements de "
        "securite du site : certificat SSL/TLS, reponse HTTP, en-tetes de "
        "securite, cookies et controles heuristiques lies aux injections SQL et XSS. ""Ces controles recherchent des indices et ne confirment pas a eux seuls une vulnerabilite."
    )

    # Page 2 : informations générales
    pdf.add_page()
    section_title(pdf, 1, "Informations generales")

    pdf.set_font("Times", "", 12)
    pdf.set_text_color(40, 40, 40)
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
        "Redirection HTTP vers HTTPS : "
        + ("Oui" if result.get("https_redirect") else "Non")
    )
    write_line(
        pdf,
        f"Test SQL Injection : {result.get('sql_injection', 'Non testable')}"
    )
    write_line(pdf, f"Test XSS : {result.get('xss', 'Non testable')}")

    # Score
    section_title(pdf, 2, "Score de securite")
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(40, 40, 40)
    write_line(pdf, f"Indice SecuWeb : {score}/100")
    pdf.ln(3)
    draw_score_bar(pdf, "Global", score)

    for label, value in result.get("score_details", {}).items():
        if value is None:
            pdf.set_font("Helvetica", "", 10)
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
            bars = ax.barh(labels, values)
            ax.set_xlim(0, 20)
            ax.set_xlabel("Score / 20")
            ax.set_title("Detail des scores de securite")

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
        write_line(pdf, f"Graphique non genere : {e}")
        pdf.set_text_color(40, 40, 40)

    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    # En-têtes
    section_title(pdf, 3, "En-tetes HTTP de securite")
    pdf.set_font("Times", "", 11)
    pdf.set_text_color(40, 40, 40)

    headers = result.get("headers", {})
    if not headers:
        write_line(pdf, "Aucune information disponible concernant les en-tetes.")
    else:
        for header, present in headers.items():
            status = "Present" if present else "Absent"
            write_line(pdf, f"- {header} : {status}")

    # Cookies
    section_title(pdf, 4, "Cookies")
    pdf.set_font("Times", "", 11)
    pdf.set_text_color(40, 40, 40)

    cookies = result.get("cookies", [])
    if not cookies:
        write_line(pdf, "Aucun cookie detecte.")
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
                    f"HttpOnly : {cookie.get('HttpOnly', 'Non determine')} | "
                    f"SameSite : {cookie.get('SameSite', 'Non determine')}"
                ),
                new_x="LMARGIN",
                new_y="NEXT",
            )
            pdf.ln(2)

    # Conclusion
    pdf.add_page()
    section_title(pdf, 5, "Conclusion")
    pdf.set_font("Times", "", 12)
    pdf.set_text_color(40, 40, 40)

    if score >= 80:
        conclusion = (
            "Les controles SecuWeb obtiennent un indice eleve. Les elements "
            "observes sont majoritairement conformes aux controles effectues. Les protections "
            "correctement configurees. Une verification periodique reste recommandee."
        )
    elif score >= 60:
        conclusion = (
            "Les controles SecuWeb obtiennent un indice globalement satisfaisant, "
            "mais certaines protections peuvent encore etre renforcees. Les elements "
            "signales comme absents ou insuffisants doivent etre examines en priorite."
        )
    elif score >= 40:
        conclusion = (
            "L indice SecuWeb est moyen. Plusieurs protections "
            "importantes sont absentes ou insuffisantes. Des mesures correctives "
            "sont recommandees afin de reduire l'exposition du site aux attaques."
        )
    else:
        conclusion = (
            "L indice SecuWeb est faible selon les controles automatises "
            "effectues. Plusieurs mesures de protection doivent etre examinees et "
            "renforcees en priorite."
        )

    write_line(pdf, conclusion)

    # Recommandations
    pdf.ln(5)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(0, 102, 204)
    write_line(pdf, "Recommandations")

    pdf.set_font("Times", "", 11)
    pdf.set_text_color(40, 40, 40)
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
                f"Configurer l'en-tete de securite {header}."
            )

    for cookie in cookies:
        name = cookie.get("name", "Sans nom")
        if not cookie.get("Secure"):
            recommendations.append(
                f"Verifier et, si approprie, activer l'attribut Secure pour le cookie {name}."
            )
        if cookie.get("HttpOnly") is False:
            recommendations.append(
                f"Activer l'attribut HttpOnly pour le cookie {name}."
            )

    if result.get("sql_injection") == "Indice détecté":
        recommendations.append(
            "Un indice d erreur SQL a ete observe. Verifier manuellement les entrees utilisateur et utiliser des requetes parametrees "
            "afin de reduire les risques d'injection SQL."
        )

    if result.get("xss") == "Réflexion détectée":
        recommendations.append(
            "Une reflexion de donnee a ete observee. Verifier le contexte de sortie, puis valider et encoder les entrees utilisateur afin de reduire les risques "
            "de Cross-Site Scripting (XSS)."
        )

    if recommendations:
        for recommendation in recommendations:
            write_line(pdf, f"- {recommendation}", 6)
    else:
        write_line(
            pdf,
            "Aucune recommandation critique n'a ete generee par les controles automatises."
        )

    # Methodologie / limites
    pdf.ln(8)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(0, 102, 204)
    write_line(pdf, "Limites de l'analyse", 6)
    pdf.set_font("Times", "", 10)
    pdf.set_text_color(70, 70, 70)
    write_line(
        pdf,
        "L'indice SecuWeb synthetise uniquement les controles executes par cet outil. "
        "L'absence d'indice SQLi ou XSS ne prouve pas l'absence de vulnerabilite. "
        "Une reflexion XSS est un signal a examiner manuellement et non une faille confirmee. "
        "Certains attributs de cookies peuvent etre indetermines lorsque la bibliotheque HTTP "
        "ne les expose pas de maniere fiable.",
        6,
    )

    # Avertissement
    pdf.ln(8)
    pdf.set_font("Times", "I", 10)
    pdf.set_text_color(100, 100, 100)
    write_line(
        pdf,
        "Ce rapport est genere automatiquement par SecuWeb. Les controles effectues "
        "constituent une analyse indicative et ne remplacent pas un audit de securite "
        "complet realise manuellement par un professionnel.",
        6,
    )

    output_path = "rapport-securite.pdf"
    pdf.output(output_path)
    return output_path