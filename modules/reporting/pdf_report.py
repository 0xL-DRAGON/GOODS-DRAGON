#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GOODS-DRAGON - PDF Report Generator
"""

import json
import os
from datetime import datetime
from core.logger import log_info, log_success, log_error

class PDFReport:
    def __init__(self, input_file, output_file=None):
        self.input_file = input_file
        self.output_file = output_file or input_file.replace('.json', '.pdf')
    
    def generate(self):
        log_info(f"Generating PDF report: {self.output_file}")
        
        try:
            with open(self.input_file, 'r') as f:
                data = json.load(f)
        except:
            log_error(f"Cannot read {self.input_file}")
            return False
        
        # Create simple HTML first
        html_file = self.output_file.replace('.pdf', '_temp.html')
        self._generate_html(data, html_file)
        
        # Try converting to PDF
        try:
            import subprocess
            subprocess.run(['wkhtmltopdf', html_file, self.output_file], 
                          capture_output=True, timeout=30)
            os.remove(html_file)
            log_success(f"PDF report: {self.output_file}")
            return True
        except:
            # Fallback: rename HTML to PDF
            os.rename(html_file, self.output_file.replace('.pdf', '.html'))
            log_info(f"wkhtmltopdf not found. HTML report saved instead.")
            return False
    
    def _generate_html(self, data, output):
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>GOODS-DRAGON Report</title>
    <style>
        body {{ font-family: Arial; background: #0a0a0a; color: #00ff00; padding: 20px; }}
        h1 {{ color: #00ff00; border-bottom: 2px solid #00ff00; }}
        h2 {{ color: #00cc00; }}
        .vuln {{ background: #1a1a1a; padding: 10px; margin: 10px 0; border-left: 3px solid #ff0000; }}
        .info {{ background: #1a1a1a; padding: 10px; margin: 10px 0; border-left: 3px solid #00ff00; }}
        .header {{ color: #888; font-size: 12px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #1a1a1a; color: #00ff00; padding: 8px; text-align: left; }}
        td {{ padding: 8px; border-bottom: 1px solid #333; }}
    </style>
</head>
<body>
    <h1>GOODS-DRAGON Scan Report</h1>
    <p class="header">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <p class="header">Tool: GOODS-DRAGON v2.0 | Owner: zeus (z4)</p>
    <hr>
"""
        
        for section, content in data.items():
            html += f"<h2>{section.upper()}</h2>"
            if isinstance(content, dict):
                html += "<table>"
                for k, v in content.items():
                    if isinstance(v, (str, int, float)):
                        html += f"<tr><td><b>{k}</b></td><td>{v}</td></tr>"
                html += "</table>"
            elif isinstance(content, list):
                for item in content[:50]:
                    html += f"<div class='info'>{json.dumps(item, indent=2)}</div>"
            else:
                html += f"<div class='info'>{content}</div>"
        
        html += """
    <hr>
    <p class="header">GOODS-DRAGON - The Dragon sees all vulnerabilities</p>
</body>
</html>"""
        
        with open(output, 'w') as f:
            f.write(html)

class TXTReport:
    def __init__(self, input_file, output_file=None):
        self.input_file = input_file
        self.output_file = output_file or input_file.replace('.json', '.txt')
    
    def generate(self):
        log_info(f"Generating TXT report: {self.output_file}")
        
        try:
            with open(self.input_file, 'r') as f:
                data = json.load(f)
        except:
            log_error(f"Cannot read {self.input_file}")
            return False
        
        lines = []
        lines.append("=" * 60)
        lines.append("GOODS-DRAGON SCAN REPORT")
        lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 60)
        lines.append("")
        
        for section, content in data.items():
            lines.append(f"[{section.upper()}]")
            lines.append("-" * 40)
            if isinstance(content, dict):
                for k, v in content.items():
                    if isinstance(v, (str, int, float)):
                        lines.append(f"  {k}: {v}")
            elif isinstance(content, list):
                for i, item in enumerate(content[:50], 1):
                    lines.append(f"  [{i}] {json.dumps(item, ensure_ascii=False)}")
            else:
                lines.append(f"  {content}")
            lines.append("")
        
        lines.append("=" * 60)
        lines.append("GOODS-DRAGON | Owner: zeus (z4)")
        
        with open(self.output_file, 'w') as f:
            f.write('\n'.join(lines))
        
        log_success(f"TXT report: {self.output_file}")
        return True
