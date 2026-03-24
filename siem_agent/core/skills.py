from langchain_core.tools import tool
from typing import Optional

@tool
def check_ip_reputation(ip_address: str) -> str:
    """
    Verifica si una dirección IP tiene mala reputación o está asociada a un Actor de Amenazas (Threat Actor).
    Útil para determinar si una IP origen es maliciosa.
    """
    if ip_address.startswith("10.") or ip_address.startswith("192.168.") or ip_address.startswith("172."):
        return f"La IP {ip_address} es un direccionamiento privado (interno)."
    if ip_address in ["198.51.100.42", "203.0.113.50", "185.0.0.1"]:
        return f"ALERTA: La IP {ip_address} está presente en bases de datos de Inteligencia de Amenazas por ataques recientes (ej. escaneo o malware)."
    
    return f"La IP {ip_address} no presenta reportes negativos en la base de datos."

@tool
def lookup_cve(cve_id: str, cvss_score: Optional[float] = None) -> str:
    """
    Busca información técnica detallada sobre un identificador CVE y permite valorar su severidad bajo el estándar CVSS v4.0.
    
    Tabla de Severidad CVSS v4.0 (Referencia):
    - CRITICAL: [9.0 - 10.0]
    - HIGH: [7.0 - 8.9]
    - MEDIUM: [4.0 - 6.9]
    - LOW: [0.1 - 3.9]
    - NONE / INFO: [0.0]
    
    Si se proporciona un score, la herramienta retornará la valoración oficial.
    """
    cve_db = {
        # CRITICAL (9.0 - 10.0)
        "CVE-2021-44228": {"name": "Log4Shell", "score": 10.0, "desc": "Ejecución Remota de Código (RCE) crítico en Apache Log4j2. Permite control total del sistema mediante inyección JNDI."},
        "CVE-2024-3094": {"name": "XZ Utils Backdoor", "score": 10.0, "desc": "Compromiso masivo de la cadena de suministro en liblzma. Introduce un backdoor en el proceso de autenticación SSH."},
        "CVE-2023-23397": {"name": "Outlook NTLM Leak", "score": 9.8, "desc": "Elevación de privilegios en Microsoft Outlook que permite el robo de hashes NTLM sin interacción del usuario."},
        
        # HIGH (7.0 - 8.9)
        "CVE-2023-38831": {"name": "WinRAR RCE", "score": 7.8, "desc": "Vulnerabilidad de ejecución de comandos al procesar archivos ZIP especialmente diseñados que contienen extensiones duplicadas."},
        "CVE-2021-31166": {"name": "HTTP.sys RCE", "score": 8.1, "desc": "Vulnerabilidad de ejecución remota de código en el stack HTTP de Windows que permite ataques tipo gusano."},

        # MEDIUM (4.0 - 6.9)
        "CVE-2019-11043": {"name": "PHP-FPM RCE", "score": 5.8, "desc": "Desbordamiento de búfer en PHP-FPM que puede llevar a la ejecución de código en configuraciones específicas de Nginx."},
        "CVE-2022-22965": {"name": "Spring4Shell", "score": 5.5, "desc": "Vulnerabilidad en Spring Framework que permite RCE bajo condiciones de despliegue muy específicas (WAR en Tomcat)."},

        # LOW (0.1 - 3.9)
        "CVE-2018-13379": {"name": "FortiOS Path Traversal", "score": 3.4, "desc": "Lectura de archivos arbitrarios del sistema (SSL VPN) que permite la extracción de credenciales de sesión en FortiGate."},
        
        # INFO (0.0)
        "CVE-2023-0001": {"name": "Generic Disclosure", "score": 0.0, "desc": "Vulnerabilidad de exposición de información no sensible que no compromete directamente la integridad del sistema."}
    }

    cve_id_clean = cve_id.upper().strip()
    data = cve_db.get(cve_id_clean)
    
    result = f"--- Análisis Técnico de Vulnerabilidad: {cve_id_clean} ---\n"
    
    if data:
        score = cvss_score if cvss_score is not None else data['score']
        result += f"Nombre Común: {data['name']}\n"
        result += f"Descripción Técnica: {data['desc']}\n"
    else:
        score = cvss_score if cvss_score is not None else 0.0
        result += (f"Nota: No existe una entrada específica en la base de datos local para {cve_id_clean}.\n"
                   f"El Agente debe utilizar su base de conocimiento LLM para describir la técnica, "
                   f"o sugerir el score si conoce los impactos.")

    # Lógica de valoración CVSS v4.0
    severity = "NONE / INFORMATIVA"
    if 9.0 <= score <= 10.0: severity = "CRITICAL"
    elif 7.0 <= score < 9.0: severity = "HIGH"
    elif 4.0 <= score < 7.0: severity = "MEDIUM"
    elif 0.1 <= score < 4.0: severity = "LOW"
    
    result += f"\n[VALORACIÓN CVSS v4.0]\n"
    result += f"- Score: {score}\n"
    result += f"- Severidad Resultante: {severity}\n"
    
    return result

@tool
def analyze_owasp_pattern(payload: str) -> str:
    """
    Analiza un payload crudo (logs, peticiones HTTP, comandos) para identificar patrones 
    correspondientes al nuevo framework OWASP Top 10 2025.
    
    Esta herramienta contiene descripciones detalladas de cada categoría 2025 para ayudar 
    en el diagnóstico preciso de la vulnerabilidad.
    """
    payload_lower = payload.lower()
    
    owasp_2025_info = {
        "A01:2025": {
            "name": "Broken Access Control",
            "desc": "Falla en la restricción de acceso que permite a usuarios actuar fuera de sus permisos (ej. Insecure Direct Object References - IDOR, elevación de privilegios, bypass de metadatos)."
        },
        "A02:2025": {
            "name": "Security Misconfiguration",
            "desc": "Configuraciones inseguras por defecto, servicios innecesarios abiertos, falta de hardening en la nube o mensajes de error detallados que exponen el stack técnico."
        },
        "A03:2025": {
            "name": "Software Supply Chain Failures",
            "desc": "Riesgos en componentes de terceros, bibliotecas vulnerables (SCA), procesos de CI/CD comprometidos o dependencias maliciosas inyectadas en el proceso de build."
        },
        "A04:2025": {
            "name": "Cryptographic Failures",
            "desc": "Fallas en la protección de datos en reposo o tránsito. Uso de algoritmos débiles (MD5, SHA1), falta de cifrado o gestión insegura de llaves criptográficas."
        },
        "A05:2025": {
            "name": "Injection",
            "desc": "Entradas no validadas que son procesadas como comandos o consultas. Incluye SQLi, NoSQLi, OS Command Injection, LDAP Injection y Cross-Site Scripting (XSS)."
        },
        "A06:2025": {
            "name": "Insecure Design",
            "desc": "Debilidades arquitectónicas que no pueden corregirse con parches de código, sino que requieren cambios de diseño (ej. falta de controles de seguridad en el flujo de negocio)."
        },
        "A07:2025": {
            "name": "Authentication Failures",
            "desc": "Debilidades en la confirmación de identidad de usuario: contraseñas débiles, falta de MFA, vulnerabilidades en 'olvidé mi clave' o sesiones que no expiran correctamente."
        },
        "A08:2025": {
            "name": "Software or Data Integrity Failures",
            "desc": "Asunción de integridad sin verificación. Incluye deserialización insegura de objetos, plugins no firmados y falta de verificación de firmas digitales en actualizaciones."
        },
        "A09:2025": {
            "name": "Security Logging and Alerting Failures",
            "desc": "Falta de visibilidad sobre incidentes. Registro insuficiente de eventos críticos (login, transacciones) o alertas que no notifican a los equipos del SOC en tiempo real."
        },
        "A10:2025": {
            "name": "Mishandling of Exceptional Conditions",
            "desc": "Fallas en el manejo de excepciones y errores que pueden filtrar secretos, exponer rutas del servidor o dejar la aplicación en un estado de denegación de servicio."
        }
    }

    results = []
    
    # Heurística de detección
    # A05:2025 - Injection (SQL, XSS, OS)
    if any(k in payload_lower for k in ["union select", "1=1", "or '1'='1", "drop table", "select * from"]):
        results.append("A05:2025 - Injection (SQL Injection detectado)")
    if any(k in payload_lower for k in ["<script", "javascript:", "onerror", "onload", "document.cookie", "alert("]):
        results.append("A05:2025 - Injection (XSS detectado)")
    if any(k in payload_lower for k in ["/bin/sh", "cmd.exe", "wget ", "curl ", "nc -e", "$(whoami)"]):
        results.append("A05:2025 - Injection (OS Command Injection detectado)")

    # A08:2025 - Integrity Failures (Deserialización / JNDI)
    if any(k in payload_lower for k in ["jndi:ldap", "jndi:rmi", "jndi:dns"]):
        results.append("A08:2025 - Software or Data Integrity Failures (Deserialización Insegura / JNDI)")

    # A01:2025 - Broken Access Control (Path Traversal)
    if any(k in payload_lower for k in ["../", "..\\", "/etc/passwd", "win.ini"]):
        results.append("A01:2025 - Broken Access Control (Path Traversal / LFI)")

    # A10:2025 - Mishandling exceptions (Stack traces common keywords)
    if any(k in payload_lower for k in ["stacktrace", "exception in thread", "nullpointerexception", "zero division error"]):
        results.append("A10:2025 - Mishandling of Exceptional Conditions (Posible fuga de información vía Stacktrace)")

    if not results:
        return ("No se detectó un patrón exacto programático de OWASP 2025. "
                "Sin embargo, el Agente debe revisar el contexto para identificar categorías de Diseño, Criptografía o Autenticación.")

    final_output = "--- Análisis Heurístico OWASP Top 10:2025 ---\n"
    for match in results:
        cat_id = match.split(" - ")[0]
        final_output += f"- {match}\n"
        final_output += f"  DESCRIPCIÓN DE RIESGO: {owasp_2025_info[cat_id]['desc']}\n"
    
    return final_output

@tool
def evaluate_mitre_attack(activity_description: str) -> str:
    """
    Evalúa una actividad sospechosa, proceso o cadena de comandos para mapearlo con la Táctica (TA) 
    y Técnica (T) correcta de MITRE ATT&CK Enterprise.
    
    Esta herramienta posee el conocimiento base de las 14 tácticas de MITRE y sus técnicas más comunes 
    para clasificar la fase del ataque en la que se encuentra el evento detectado por el SIEM.
    """
    desc = activity_description.lower()
    
    mitre_enterprise_matrix = {
        "TA0043": {"name": "Reconnaissance", "desc": "Búsqueda de información sobre la víctima (ej. escaneo de puertos, búsqueda de subdominios, recolección de correos)."},
        "TA0042": {"name": "Resource Development", "desc": "Preparación de infraestructura para el ataque (ej. compra de dominios, configuración de servidores C2, desarrollo de malware)."},
        "TA0001": {"name": "Initial Access", "desc": "Esfuerzos para entrar en la red (ej. Phishing, Exploits en aplicaciones públicas como T1190, uso de cuentas válidas)."},
        "TA0002": {"name": "Execution", "desc": "Ejecución de código malicioso (ej. intérpretes de comandos Powershell/Bash T1059, WMI, herramientas de administración)."},
        "TA0003": {"name": "Persistence", "desc": "Mantener acceso a pesar de reinicios o cambios de credenciales (ej. tareas programadas T1053, nuevos servicios, llaves de registro)."},
        "TA0004": {"name": "Privilege Escalation", "desc": "Ganar permisos de mayor nivel (ej. explotación de Kernel, manipulación de tokens de acceso T1134)."},
        "TA0005": {"name": "Defense Evasion", "desc": "Evitar ser detectado (ej. borrado de logs T1070, ofuscación, desactivación de software de seguridad T1562)."},
        "TA0006": {"name": "Credential Access", "desc": "Robo de identidades (ej. Brute Force T1110, dumping de memoria LSASS T1003, keylogging)."},
        "TA0007": {"name": "Discovery", "desc": "Exploración interna para entender el entorno (ej. listar usuarios T1087, descubrir servidores T1018, sniffing)."},
        "TA0008": {"name": "Lateral Movement", "desc": "Moverse a través de la red (ej. Remote Services como RDP/SSH T1021, SMB, paso del hash T1550)."},
        "TA0009": {"name": "Collection", "desc": "Recolección de datos de interés (ej. capturas de pantalla, robo de archivos T1005, acceso a emails)."},
        "TA0011": {"name": "Command and Control", "desc": "Comunicación con el servidor atacante (ej. protocolos de capa de aplicación T1071, Beaconing, túneles DNS)."},
        "TA0010": {"name": "Exfiltration", "desc": "Extracción de datos fuera de la red (ej. Exfiltración sobre C2 T1041, uso de nubes públicas)."},
        "TA0040": {"name": "Impact", "desc": "Daño final u objetivos finales del ataque (ej. Ransomware/Cifrado T1486, borrado de datos, defacement)."}
    }

    results = []

    # Mapeo lógico por palabras clave
    if any(k in desc for k in ["exploit", "cve", "phishing", "public-facing", "valid account"]):
        results.append("TA0001 - Initial Access")
    if any(k in desc for k in ["powershell", "base64", "cmd.exe", "/bin/bash", "script", "wmi", "execution"]):
        results.append("TA0002 - Execution")
    if any(k in desc for k in ["scheduled task", "cron job", "persistence", "registry run"]):
        results.append("TA0003 - Persistence")
    if any(k in desc for k in ["lsass", "mimikatz", "shadow", "hash", "brute force", "credential", "dumping"]):
        results.append("TA0006 - Credential Access")
    if any(k in desc for k in ["rdp", "ssh", "smb", "lateral", "psexec", "rpc"]):
        results.append("TA0008 - Lateral Movement")
    if any(k in desc for k in ["delete logs", "clear logs", "indicator removal", "evasion", "disable antivirus"]):
        results.append("TA0005 - Defense Evasion")
    if any(k in desc for k in ["beacon", "c2", "c&c", "botnet", "dns tunnel", "exfiltration"]):
        results.append("TA0011 - Command and Control")
    if any(k in desc for k in ["ransomware", "encrypt", "delete files", "impact", "dos"]):
        results.append("TA0040 - Impact")

    if not results:
        return ("No se pudo mapear automáticamente a una táctica MITRE mediante palabras clave simples. "
                "El Agente SOC debe usar su razonamiento experto para clasificar el incidente en las 14 tácticas Enterprise.")

    final_report = "--- Análisis Detallado MITRE ATT&CK Enterprise ---\n"
    for tactic_id in set(results):
        tid = tactic_id.split(" - ")[0]
        final_report += f"- Táctica Identificada: {mitre_enterprise_matrix[tid]['name']} ({tid})\n"
        final_report += f"  DESCRIPCIÓN DE LA FASE: {mitre_enterprise_matrix[tid]['desc']}\n"
    
    final_report += "\n[RECOMENDACIÓN]: El analista debe correlacionar estas tácticas para armar la Kill Chain del ataque."
    
    return final_report

# Agregamos las nuevas herramientas a la lista
AGENT_TOOLS = [check_ip_reputation, lookup_cve, analyze_owasp_pattern, evaluate_mitre_attack]
