# BBRecon

Framework modular de reconocimiento y pruebas básicas para bug bounty, escrito en Python. Pensado para ordenar el flujo de trabajo de un tester: enumerar, probar, validar hallazgos y generar un reporte.

> **Uso autorizado únicamente.** Usalo solo contra objetivos dentro del alcance de un programa de bug bounty, laboratorios propios o entornos de prueba con permiso. Usarlo contra sistemas sin autorización es ilegal.

## Requisitos

- Python 3.10 o superior. El núcleo usa solo la biblioteca estándar, no hay que instalar paquetes.
- Opcionales, si querés usar las integraciones: `nmap`, `ffuf`, `nuclei` y una lista de palabras (por ejemplo SecLists).

```bash
# ejemplos de instalación de las herramientas externas
sudo apt install nmap seclists
go install github.com/ffuf/ffuf/v2@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

## Uso

```bash
# modo interactivo (menú)
python main.py -t target.com

# recon completo
python main.py -t target.com recon --all

# solo subdominios y headers
python main.py -t target.com recon --subdomains --headers

# pruebas de vulnerabilidades sobre una URL concreta
python main.py -t "https://target.com/search?q=test" vuln --xss --sqli

# integraciones externas
python main.py -t target.com integrations --nmap
python main.py -t target.com integrations --ffuf --wordlist /ruta/wordlist.txt
python main.py -t target.com integrations --nuclei

# reporte
python main.py -t target.com report --format md
```

Las integraciones con servicios externos (Shodan, Google Dork, Burp Suite, Acunetix) reciben su clave por argumento de línea de comandos. No se guardan en archivos del proyecto.

## Módulos

| Carpeta | Qué hace |
| --- | --- |
| `core/` | Sesión y hallazgos, cliente HTTP, limitador de velocidad, banner y menú interactivo |
| `modules/recon.py` | Subdominios (DNS + crt.sh), puertos comunes, detección de tecnologías, análisis de headers |
| `modules/crawler.py`, `js_analyzer.py`, `param_discovery.py`, `endpoint_aggregator.py` | Rastreo, análisis de JavaScript, descubrimiento de parámetros y consolidación de endpoints |
| `modules/vuln.py`, `fuzzer.py`, `validator.py` | XSS, SQLi, SSRF, IDOR, LFI, fuzzing y validación de hallazgos para reducir falsos positivos |
| `modules/http_probe.py`, `dns_resolver.py` | Sondeo HTTP y resolución DNS |
| `integrations/runner.py` | nmap, ffuf, nuclei y otras herramientas externas |
| `reports/generator.py` | Reportes en Markdown, JSON y texto |
| `docs/` | Notas de trabajo: reglas, fuentes de aprendizaje y tareas |

## Salida

Cada sesión crea una carpeta `output/<objetivo>/` con el estado (`session.json`), el reporte (`report.md`) y los resultados crudos de nmap, ffuf y nuclei. Esa carpeta está en `.gitignore`: puede contener datos de objetivos reales.

## Estado

Proyecto personal de aprendizaje. Los detectores usan payloads y heurísticas simples, así que los resultados hay que confirmarlos a mano antes de reportar nada.
