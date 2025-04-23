import os
import subprocess
import json
import time
import datetime
import smtplib
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from rich import print
from rich.console import Console
from rich.table import Table

CONFIG_PATH = os.path.expanduser("~/.sentinelvas_config.json")
console = Console()


def load_config():
    if not os.path.exists(CONFIG_PATH):
        return setup_config()
    with open(CONFIG_PATH, 'r') as f:
        return json.load(f)

def setup_config():
    config = {}
    console.print("[bold cyan]>>> Configuração Inicial do SentinelVAS[/bold cyan]")
    config['email_from'] = input("Email remetente: ")
    config['email_to'] = input("Email destino: ")
    config['smtp_server'] = input("Servidor SMTP: ")
    config['smtp_port'] = int(input("Porta SMTP: "))
    config['smtp_user'] = input("Usuário SMTP: ")
    config['smtp_pass'] = input("Senha SMTP: ")
    config['zabbix_sender'] = input("Caminho do zabbix_sender: ") or "/usr/bin/zabbix_sender"
    config['zabbix_host'] = input("Hostname no Zabbix: ")
    config['zabbix_key'] = input("Chave da métrica no Zabbix: ")
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=4)
    return config


def run_openvas_scan():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"openvas_report_{timestamp}.json"
    command = f"gvm-cli --gmp-username admin --gmp-password admin socket --xml '<get_reports details=\"1\"/>' > {output_file}"
    os.system(command)
    return output_file


def parse_report(filepath):
    with open(filepath, 'r') as f:
        data = f.read()
    # Simulação de parsing de relatório
    return [{
        "hostname": socket.gethostname(),
        "cve_id": "CVE-2024-1234",
        "severity": 9.8,
        "summary": "Falha crítica de execução remota",
        "timestamp": datetime.datetime.now().isoformat()
    }]


def send_email_alert(config, findings):
    msg = MIMEMultipart()
    msg['From'] = config['email_from']
    msg['To'] = config['email_to']
    msg['Subject'] = "[SentinelVAS] CVEs detectadas no último scan"
    body = "\n\n".join([
        f"CVE: {f['cve_id']}\nSeveridade: {f['severity']}\nResumo: {f['summary']}\nTimestamp: {f['timestamp']}"
        for f in findings
    ])
    msg.attach(MIMEText(body, 'plain'))
    try:
        server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
        server.starttls()
        server.login(config['smtp_user'], config['smtp_pass'])
        server.sendmail(config['email_from'], config['email_to'], msg.as_string())
        server.quit()
        print("[green]Alerta de email enviado com sucesso.[/green]")
    except Exception as e:
        print(f"[red]Erro ao enviar email: {e}[/red]")


def send_to_zabbix(config, findings):
    score = max([f['severity'] for f in findings]) if findings else 0
    cmd = [
        config['zabbix_sender'], '-z', '127.0.0.1', '-s', config['zabbix_host'],
        '-k', config['zabbix_key'], '-o', str(score)
    ]
    subprocess.run(cmd)
    print("[blue]Score enviado ao Zabbix.[/blue]")


def export_findings(findings, export_format='json'):
    now = datetime.datetime.now().strftime("%Y%m%d")
    filename = f"relatorio_cves_{now}.{export_format}"
    with open(filename, 'w') as f:
        if export_format == 'json':
            json.dump(findings, f, indent=2)
        elif export_format == 'csv':
            f.write("hostname,cve_id,severity,summary,timestamp\n")
            for fnd in findings:
                f.write(f"{fnd['hostname']},{fnd['cve_id']},{fnd['severity']},{fnd['summary']},{fnd['timestamp']}\n")
    print(f"[green]Relatório exportado para {filename}[/green]")


def menu():
    config = load_config()
    while True:
        print("\n[bold magenta]=== SentinelVAS CLI ===[/bold magenta]")
        print("[1] Rodar escaneamento agora")
        print("[2] Gerar relatório JSON")
        print("[3] Exportar CSV")
        print("[4] Enviar alertas manualmente")
        print("[5] Configurações")
        print("[0] Sair")
        opt = input("> Escolha: ")

        if opt == '1':
            report_file = run_openvas_scan()
            findings = parse_report(report_file)
            send_to_zabbix(config, findings)
            send_email_alert(config, findings)

        elif opt == '2':
            findings = parse_report(run_openvas_scan())
            export_findings(findings, export_format='json')

        elif opt == '3':
            findings = parse_report(run_openvas_scan())
            export_findings(findings, export_format='csv')

        elif opt == '4':
            findings = parse_report(run_openvas_scan())
            send_email_alert(config, findings)

        elif opt == '5':
            os.remove(CONFIG_PATH)
            config = setup_config()

        elif opt == '0':
            break
        else:
            print("[red]Opção inválida.[/red]")


if __name__ == "__main__":
    menu()
