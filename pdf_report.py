from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
import datetime
import os

def generate_pdf_report(log_file="logs/detected_logs.txt", root_file="logs/root_cause_report.txt", graph_img="static/graph.png", output="logs/Attack_Report.pdf"):
    c = canvas.Canvas(output, pagesize=A4)
    width, height = A4

    # Header
    c.setFont("Helvetica-Bold", 18)
    c.drawString(1 * inch, height - 1 * inch, "🛡️ Cyberattack Incident Report")

    c.setFont("Helvetica", 12)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")
    c.drawString(1 * inch, height - 1.3 * inch, f"Generated on: {timestamp}")

    # Section: Logs
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1 * inch, height - 1.8 * inch, "📜 Incident Logs")
    y = height - 2.1 * inch
    c.setFont("Helvetica", 10)

    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            for line in f.readlines()[:40]:  # Limit log lines
                if y < 1 * inch:
                    c.showPage()
                    y = height - 1 * inch
                    c.setFont("Helvetica", 10)
                c.drawString(1 * inch, y, line.strip())
                y -= 12

    # Section: Root Cause Summary
    y -= 20
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1 * inch, y, "🧠 Root Cause Analysis")
    y -= 20
    c.setFont("Helvetica", 10)

    if os.path.exists(root_file):
        with open(root_file, "r") as f:
            for line in f.readlines()[:20]:  # Limit root cause lines
                if y < 1 * inch:
                    c.showPage()
                    y = height - 1 * inch
                    c.setFont("Helvetica", 10)
                c.drawString(1 * inch, y, line.strip())
                y -= 12

    # Section: Graph Image
    c.showPage()
    c.setFont("Helvetica-Bold", 14)
    c.drawString(1 * inch, height - 1 * inch, "🕸️ Attack Graph")
    if os.path.exists(graph_img):
        c.drawImage(graph_img, 1 * inch, height - 6 * inch, width=5.5 * inch, preserveAspectRatio=True, mask='auto')

    # Save PDF
    c.save()
    print(f"✅ PDF report generated: {output}")
