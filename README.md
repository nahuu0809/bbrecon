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

## Créditos

BBRecon no incluye código de terceros: orquesta herramientas externas que hay que instalar aparte, cada una con su propia licencia. Todo el mérito del trabajo de fondo es de sus autores.

| Herramienta | Uso en BBRecon | Enlace |
| --- | --- | --- |
| nmap | Escaneo de puertos y servicios | https://nmap.org |
| ffuf | Fuerza bruta de directorios | https://github.com/ffuf/ffuf |
| nuclei y subfinder | Plantillas de vulnerabilidades y subdominios | https://github.com/projectdiscovery/nuclei · https://github.com/projectdiscovery/subfinder |
| httpx | Sondeo HTTP | https://github.com/projectdiscovery/httpx |
| Amass | Enumeración de subdominios | https://github.com/owasp-amass/amass |
| massdns | Resolución DNS masiva | https://github.com/blechschmidt/massdns |
| gau y waybackurls | URLs históricas | https://github.com/lc/gau · https://github.com/tomnomnom/waybackurls |
| LinkFinder | Endpoints en archivos JavaScript | https://github.com/GerbenJavado/LinkFinder |
| Dalfox | Pruebas de XSS | https://github.com/hahwul/dalfox |
| Jaeles | Escaneo basado en firmas | https://github.com/jaeles-project/jaeles |
| 403bypasser | Pruebas de bypass de 403 | https://github.com/yunemse48/403bypasser |
| Keye y keyleak-detector | Detección de claves expuestas | https://github.com/s0md3v/Keye · https://github.com/Amal-David/keyleak-detector |

Para el recon de subdominios también consulta [crt.sh](https://crt.sh) (transparencia de certificados). Las notas de `docs/` recopilan recursos de aprendizaje y repositorios como [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings), [sqlmap](https://github.com/sqlmapproject/sqlmap) y [katana](https://github.com/projectdiscovery/katana).

## Licencia

Código bajo [licencia MIT](LICENSE). © 2026 Nahuel Emiliano Diaz.
