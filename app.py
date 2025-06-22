from flask import Flask, render_template, request, send_file
from scanner import analyse_site, generate_pdf
from datetime import datetime

app = Flask(__name__)
last_report = {}

@app.route("/", methods=["GET", "POST"])
def index():
    global last_report
    if request.method == "POST":
        url = request.form["url"]
        last_report = analyse_site(url)
        last_report["timestamp"] = datetime.now().strftime("%d/%m/%Y %H:%M")
        return render_template("index.html", result=last_report)
    return render_template("index.html", result=None)

@app.route("/rapport_securite.pdf")
def download_pdf():
    global last_report
    if not last_report:
        return "Aucun rapport disponible", 404
    generate_pdf(last_report)
    return send_file("rapport-securite.pdf", as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
