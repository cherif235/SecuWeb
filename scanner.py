import ssl, socket, os, requests, tempfile, matplotlib.pyplot as plt
from urllib.parse import urlparse, urljoin
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime
from fpdf import FPDF

# ───────────────────────────── Analyse du site ────────────────────────────────
def analyse_site(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        resp = requests.get(url, timeout=8, allow_redirects=True)
    except Exception:
        resp = None

    report = {
        "url": url,
        "http_code": resp.status_code if resp else "Erreur",
        "ssl": check_ssl(url),
        "headers": header_audit(resp.headers if resp else {}),
        "cookies": cookie_audit(resp.cookies if resp else []),
        "sql_injection": sql_test(url),
        "xss": xss_test(url),
        "https_redirect": https_redirect(url),
    }
    report["score"], report["score_details"] = compute_score(report)
    return report

# ─── Tests particuliers ───────────────────────────────────────────────────────
def check_ssl(url):
    host = urlparse(url).hostname
    res = {"valid": False}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(5)
            s.connect((host, 443))
            cert_bin = s.getpeercert(True)
        cert = x509.load_der_x509_certificate(cert_bin, default_backend())
        res = {
            "valid": True,
            "expire_in_days": (cert.not_valid_after - datetime.utcnow()).days,
        }
    except Exception as e:
        res["error"] = str(e)
    return res


def header_audit(h):
    wanted = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ]
    return {k: k in h for k in wanted}


def cookie_audit(cookies):
    out = []
    for c in cookies:
        secure = c.secure
        httponly = c.has_nonstandard_attr("HttpOnly")
        samesite = "None"
        if hasattr(c, "_rest") and isinstance(c._rest, dict):
            samesite = c._rest.get("samesite", c._rest.get("SameSite", "None"))
        out.append(
            {
                "name": c.name,
                "Secure": secure,
                "HttpOnly": httponly,
                "SameSite": samesite,
            }
        )
    return out


def sql_test(url):
    payload = "' OR 1=1--"
    try:
        r = requests.get(urljoin(url, "?q=" + payload), timeout=5)
        vuln = any(x in r.text.lower() for x in ("sql", "syntax", "warning"))
        return "Vulnerable" if vuln else "Sain"
    except Exception:
        return "Non testable"


def xss_test(url):
    payload = "<script>alert(1)</script>"
    joiner = "&" if "?" in url else "?"
    try:
        r = requests.get(url + joiner + "x=" + payload, timeout=5)
        vuln = payload.lower() in r.text.lower()
        return "Vulnerable" if vuln else "Sain"
    except Exception:
        return "Non testable"


def https_redirect(url):
    host = urlparse(url).hostname
    try:
        r = requests.get("http://" + host, timeout=5, allow_redirects=True)
        return r.url.startswith("https://")
    except Exception:
        return False


# ─── Calcul du score ──────────────────────────────────────────────────────────
def compute_score(r):
    det, total = {}, 0
    ssl_s = 20 if r["ssl"].get("valid") else 0
    if r["ssl"].get("valid") and r["ssl"].get("expire_in_days", 0) < 30:
        ssl_s -= 5
    det["SSL"] = ssl_s
    total += ssl_s

    http_s = 20 if r["http_code"] in (200, 301, 302) else 0
    det["HTTP"] = http_s
    total += http_s

    sql_s = 20 if r["sql_injection"] == "Sain" else 0
    det["SQLi"] = sql_s
    total += sql_s

    xss_s = 20 if r["xss"] == "Sain" else 0
    det["XSS"] = xss_s
    total += xss_s

    hdr_s = min(sum(4 for v in r["headers"].values() if v), 20)
    det["Headers"] = hdr_s
    total += hdr_s
    return total, det


# ────────────────────────────── Génération PDF ────────────────────────────────
class CustomPDF(FPDF):
    def header(self):
        if self.page_no() == 1 and os.path.exists("static/logo.png"):
            self.image("static/logo.png", x=172, y=3, w=25)  # Position du logo

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 9)
        self.set_text_color(110, 110, 110)
        self.cell(
            0,
            10,
            f"AbakarTech - Rapport généré automatiquement | Page {self.page_no()}/{{nb}}",
            0,
            0,
            "C",
        )


def draw_score_bar(pdf, label, percent, y):
    x_bar, max_w, h = 60, 120, 6
    bar_w = (percent / 100) * max_w
    fill = (0, 153, 76) if percent >= 80 else (255, 140, 0) if percent >= 50 else (204, 0, 0)

    pdf.set_fill_color(230, 230, 230)
    pdf.rect(x_bar, y, max_w, h, "F")
    pdf.set_fill_color(*fill)
    pdf.rect(x_bar, y, bar_w, h, "F")

    pdf.set_xy(20, y - 1)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(0)
    pdf.cell(30, 8, label)

    pdf.set_xy(x_bar + max_w + 2, y - 1)
    pdf.cell(20, 8, f"{int(percent)}%")


def generate_pdf(result):
    pdf = CustomPDF()
    pdf.alias_nb_pages()

    # ── Page 1 : Sommaire ────────────────────────────────────────────────
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 17)
    pdf.set_text_color(33, 37, 41)
    pdf.cell(0, 12, "Rapport de sécurité", ln=True, align="C")
    pdf.set_draw_color(0, 102, 204)
    pdf.set_line_width(0.8)
    pdf.line(70, 25, 140, 25)
    pdf.ln(14)

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Sommaire", ln=True, align="C")
    pdf.set_draw_color(0, 51, 102)
    pdf.set_line_width(0.6)
    pdf.line(20, pdf.get_y(), 190, pdf.get_y())

    pdf.set_font("Helvetica", "", 12)
    pdf.set_text_color(40, 40, 40)
    toc = [
        ("Informations générales", 2),
        ("Score global & detail", 3),
        ("En-tetes de sécurité", 4),
        ("Cookies", 5),
        ("Conclusion", 6),
    ]
    pdf.set_fill_color(240, 248, 255)
    y0 = pdf.get_y() + 2
    for i, (lbl, pno) in enumerate(toc, 1):
        pdf.set_xy(20, y0 + (i - 1) * 9)
        dots = "." * (46 - len(lbl))
        pdf.cell(170, 8, f"{i}. {lbl} {dots} {pno}", ln=True, fill=True)

    pdf.ln(10)
    pdf.set_font("Helvetica", "", 11)
    pdf.multi_cell(
        0,
        8,
        "Ce rapport présente une analyse de sécurité détaillée du site web audité. "
        "Vous y trouverez des résultats techniques clairs et exploitables pour renforcer votre sécurité.",
    )

    # ── Page 2 : Informations générales & scores ────────────────────────
    pdf.add_page()
    pdf.set_fill_color(33, 53, 85)
    pdf.rect(0, 0, 210, 25, "F")
    if os.path.exists("static/logo.png"):
        pdf.image("static/logo.png", x=172, y=3, w=25)
    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(255, 255, 255)
    pdf.set_xy(10, 8)
    pdf.cell(0, 10, "Rapport d'analyse de sécurité", align="C")
    pdf.ln(22)
    pdf.set_draw_color(180, 180, 180)
    pdf.set_line_width(0.4)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(8)

    # 1. Infos générales
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(0, 102, 204)
    pdf.cell(0, 10, "1. Informations générales", ln=True)

    pdf.set_font("Times", "", 12)
    pdf.set_text_color(40, 40, 40)
    ts = result.get("timestamp") or datetime.now().strftime("%d/%m/%Y %H:%M")
    pdf.cell(0, 8, f"Analyse effectuée le : {ts}", ln=True)
    pdf.cell(0, 8, f"URL : {result['url']}", ln=True)
    pdf.cell(0, 8, f"Code HTTP : {result['http_code']}", ln=True)
    pdf.cell(0, 8, f"SSL valide : {result['ssl']['valid']}", ln=True)
    if result["ssl"]["valid"]:
        pdf.cell(0, 8, f"Expire dans : {result['ssl']['expire_in_days']} jours", ln=True)
    pdf.cell(0, 8, f"Redirection HTTPS : {result['https_redirect']}", ln=True)
    pdf.cell(0, 8, f"Injection SQL : {result['sql_injection']}", ln=True)
    pdf.cell(0, 8, f"XSS : {result['xss']}", ln=True)

    # 2. Score global & détail
    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(0, 102, 204)
    pdf.cell(0, 10, "2. Score global & detail", ln=True)

    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(40, 40, 40)
    pdf.cell(0, 8, f"Score global : {result['score']} / 100", ln=True)

    y = pdf.get_y() + 2
    draw_score_bar(pdf, "Score global", result["score"], y)
    pdf.ln(12)

    for k, v in result["score_details"].items():
        pct = (v / 20) * 100
        y = pdf.get_y() + 2
        draw_score_bar(pdf, k, pct, y)
        pdf.ln(12)

    # Légende couleurs
    legend_y = pdf.get_y() + 2
    legend = [(">= 80 %", (0, 153, 76)), ("50-79 %", (255, 140, 0)), ("< 50 %", (204, 0, 0))]
    pdf.set_font("Helvetica", "", 9)
    for i, (txt, rgb) in enumerate(legend):
        pdf.set_fill_color(*rgb)
        pdf.rect(20 + i * 35, legend_y, 5, 5, "F")
        pdf.set_xy(27 + i * 35, legend_y - 1)
        pdf.cell(0, 6, txt)
    pdf.ln(10)

    # Graphique horizontal
    try:
        labels = list(result["score_details"].keys())
        values = list(result["score_details"].values())
        fig, ax = plt.subplots(figsize=(4.5, 2.4))
        bars = ax.barh(labels, values, color="steelblue")
        ax.set_xlim(0, 20)
        ax.set_xlabel("Score / 20")
        for bar in bars:
            w = bar.get_width()
            ax.text(w + 0.3, bar.get_y() + bar.get_height() / 2, f"{int(w)}",
                    va="center", fontsize=8)
        plt.tight_layout()
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".png")
        fig.savefig(tmp.name, dpi=150)
        plt.close(fig)
        pdf.image(tmp.name, x=40, y=pdf.get_y(), w=120)
        pdf.ln(58)
        os.unlink(tmp.name)
    except Exception as e:
        pdf.set_text_color(200, 0, 0)
        pdf.cell(0, 8, f"[Graphique non généré : {e}]", ln=True)
        pdf.set_text_color(0)

    # 3. En-têtes de sécurité
    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(0, 102, 204)
    pdf.cell(0, 10, "3. En-tetes de sécurité", ln=True)

    pdf.set_font("Times", "", 12)
    pdf.set_text_color(40, 40, 40)
    for h, v in result["headers"].items():
        pdf.cell(0, 8, f"- {h} : {'Présent' if v else 'Absent'}", ln=True)

    # 4. Cookies
    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(0, 102, 204)
    pdf.cell(0, 10, "4. Cookies", ln=True)

    pdf.set_font("Times", "", 12)
    pdf.set_text_color(40, 40, 40)
    if not result["cookies"]:
        pdf.cell(0, 8, "Aucun cookie détecté", ln=True)
    else:
        for c in result["cookies"]:
            line = (
                f"{c['name']} - Secure={c['Secure']} | "
                f"HttpOnly={c['HttpOnly']} | SameSite={c['SameSite']}"
            )
            pdf.multi_cell(0, 8, line)

    # ── Page 3 : Conclusion ─────────────────────────────────────────────
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(0, 102, 204)
    pdf.cell(0, 10, "5. Conclusion", ln=True)

    pdf.ln(4)
    pdf.set_font("Times", "", 12)
    pdf.set_text_color(40, 40, 40)

    score = result.get("score", 0)
    if score >= 80:
        concl = (
            "Le site presente un tres bon niveau de securite. "
            "Aucun point critique n'a ete detecte."
        )
    elif score >= 60:
        concl = (
            "Le site est globalement securise, mais quelques ameliorations "
            "sont recommandees pour atteindre un niveau optimal."
        )
    elif score >= 40:
        concl = (
            "Le niveau de securite est moyen. Plusieurs mesures correctives "
            "doivent etre envisagees rapidement."
        )
    else:
        concl = (
            "Le site presente de nombreuses failles critiques. "
            "Une intervention urgente est necessaire."
        )

    pdf.multi_cell(0, 8, concl)

    pdf.ln(10)
    pdf.set_font("Times", "I", 11)
    pdf.set_text_color(100, 100, 100)
    pdf.multi_cell(
        0,
        8,
        "Ce resume est genere automatiquement a partir des resultats precedents "
        "et ne remplace pas un audit complet realise par un expert.",
    )

    # ── Sauvegarde ──────────────────────────────────────────────────────
    pdf.output("rapport-securite.pdf")
