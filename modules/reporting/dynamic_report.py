#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import csv
import os
from datetime import datetime
from core.logger import log_info, log_success

class DynamicReport:
    def __init__(self, json_file, output_dir="reports/"):
        self.json_file = json_file
        self.output_dir = output_dir
        self.data = {}
        self.base_name = os.path.splitext(os.path.basename(json_file))[0]

    def load_data(self):
        try:
            with open(self.json_file, 'r', encoding='utf-8') as f:
                self.data = json.load(f)
            return True
        except Exception as e:
            log_info(f"Error loading JSON: {e}")
            return False

    def generate_html(self):
        html = f"""
        <!DOCTYPE html>
        <html>
        <head><title>GOODS-DRAGON - Report</title>
        <style>
            body {{ font-family: Arial; background: #0d1117; color: #c9d1d9; padding: 20px; }}
            .container {{ max-width: 1000px; margin: auto; background: #161b22; padding: 20px; border-radius: 10px; }}
            h1 {{ color: #58a6ff; }}
            .card {{ background: #21262d; padding: 15px; margin: 10px 0; border-radius: 8px; }}
            pre {{ background: #0d1117; padding: 10px; border-radius: 5px; overflow-x: auto; }}
        </style>
        </head>
        <body>
        <div class="container">
            <h1>🐉 GOODS-DRAGON - Security Report</h1>
            <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Author:</strong> zeus (z4) | @iM_z4</p>
            <hr>
            <div class="card">
                <pre>{json.dumps(self.data, indent=2, ensure_ascii=False)}</pre>
            </div>
        </div>
        </body>
        </html>
        """
        path = f"{self.output_dir}{self.base_name}.html"
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)
        log_success(f"HTML report: {path}")

    def generate_markdown(self):
        json_str = json.dumps(self.data, indent=2, ensure_ascii=False)
        md = "# 🐉 GOODS-DRAGON - Security Report\n"
        md += f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        md += "**Author:** zeus (z4) | @iM_z4\n\n"
        md += "## Results\n\n```json\n"
        md += json_str
        md += "\n```\n"
        path = f"{self.output_dir}{self.base_name}.md"
        with open(path, 'w', encoding='utf-8') as f:
            f.write(md)
        log_success(f"Markdown report: {path}")

    def generate_json(self):
        path = f"{self.output_dir}{self.base_name}.json"
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
        log_success(f"JSON report: {path}")

    def generate_csv(self):
        path = f"{self.output_dir}{self.base_name}.csv"
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Module", "Key", "Value"])
            for key, value in self.data.items():
                if isinstance(value, dict):
                    for k, v in value.items():
                        writer.writerow([key, k, str(v)[:100]])
        log_success(f"CSV report: {path}")

    def generate_pdf(self):
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.pdfgen import canvas
            path = f"{self.output_dir}{self.base_name}.pdf"
            c = canvas.Canvas(path, pagesize=letter)
            c.drawString(100, 750, "🐉 GOODS-DRAGON - Security Report")
            c.drawString(100, 730, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            c.drawString(100, 710, f"Author: zeus (z4) | @iM_z4")
            c.drawString(100, 680, "Summary:")
            y = 660
            for key, value in self.data.items():
                c.drawString(100, y, f"- {key}: {str(value)[:50]}...")
                y -= 20
            c.save()
            log_success(f"PDF report: {path}")
        except Exception as e:
            log_info(f"PDF generation skipped: {e}")

    def generate_all(self):
        if not self.load_data():
            return
        os.makedirs(self.output_dir, exist_ok=True)
        self.generate_html()
        self.generate_markdown()
        self.generate_json()
        self.generate_csv()
        self.generate_pdf()
