# containersec_enhanced.py

import os
import subprocess
import json
import datetime
import argparse
from rich.console import Console
from rich.table import Table
from rich.progress import track
from urllib.parse import quote_plus

console = Console()

# Funções principais

def scan_with_trivy(image):
    output_file = f"trivy_report_{image.replace('/', '_').replace(':', '_')}.json"
    cmd = ["trivy", "image", "--format", "json", "-o", output_file, image]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return output_file

def parse_trivy_report(report_file, threshold):
    with open(report_file, 'r') as f:
        data = json.load(f)
    findings = []
    for result in data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            score = vuln.get('CVSS', {}).get('nvd', {}).get('V3Score') or vuln.get('CVSS', {}).get('nvd', {}).get('V2Score', 0)
            if score >= threshold:
                findings.append({
                    "package": vuln.get('PkgName'),
                    "severity": vuln.get('Severity'),
                    "cve_id": vuln.get('VulnerabilityID'),
                    "cvss": score,
                    "title": vuln.get('Title', 'N/A'),
                    "fixed": vuln.get('FixedVersion', 'N/A'),
                })
    return findings

def export_report(findings, image, formats):
    ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    for fmt in formats:
        filename = f"report_{image.replace('/', '_').replace(':', '_')}_{ts}.{fmt}"
        with open(filename, 'w') as f:
            if fmt == 'json':
                json.dump(findings, f, indent=2)
            elif fmt == 'csv':
                f.write("package,cve_id,severity,cvss,fixed_version,title\n")
                for item in findings:
                    f.write(f"{item['package']},{item['cve_id']},{item['severity']},{item['cvss']},{item['fixed']},{item['title']}\n")
            elif fmt == 'html':
                f.write("<html><body><h2>Relatório de Vulnerabilidades</h2><table border=1>")
                f.write("<tr><th>Package</th><th>CVE</th><th>Severity</th><th>CVSS</th><th>Fix</th><th>Title</th></tr>")
                for item in findings:
                    f.write(f"<tr><td>{item['package']}</td><td>{item['cve_id']}</td><td>{item['severity']}</td><td>{item['cvss']}</td><td>{item['fixed']}</td><td>{item['title']}</td></tr>")
                f.write("</table></body></html>")
        console.print(f"[green]Relatório exportado:[/green] {filename}")

def print_summary(findings):
    table = Table(title="Resumo das Vulnerabilidades Críticas")
    table.add_column("CVE", style="red")
    table.add_column("Severidade")
    table.add_column("Score CVSS")
    table.add_column("Pacote")
    table.add_column("Correção Disponível")
    for f in findings:
        table.add_row(f["cve_id"], f["severity"], str(f["cvss"]), f["package"], f["fixed"])
    console.print(table)

# CLI

def main():
    parser = argparse.ArgumentParser(description="Scanner de imagens Docker com Trivy + exportação de relatórios.")
    parser.add_argument('--images', nargs='+', help="Imagens Docker para escanear", required=True)
    parser.add_argument('--cvss-threshold', type=float, default=7.0, help="CVSS mínimo para reportar")
    parser.add_argument('--export-formats', nargs='+', default=['json'], choices=['json', 'csv', 'html'], help="Formatos de exportação")
    parser.add_argument('--silent', action='store_true', help="Modo silencioso (sem prints detalhados)")
    parser.add_argument('--ci', action='store_true', help="Modo CI/CD (exit 1 se vulnerabilidades críticas forem encontradas)")
    args = parser.parse_args()

    exit_code = 0

    for image in track(args.images, description="Escaneando imagens..."):
        report = scan_with_trivy(image)
        findings = parse_trivy_report(report, args.cvss_threshold)
        if findings:
            if not args.silent:
                console.print(f"[bold red]\nVulnerabilidades críticas encontradas na imagem {image}:[/bold red]")
                print_summary(findings)
            export_report(findings, image, args.export_formats)
            exit_code = 1 if args.ci else exit_code
        else:
            console.print(f"[green]Imagem segura:[/green] {image}")

    exit(exit_code)

if __name__ == '__main__':
    main()
