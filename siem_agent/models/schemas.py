from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class SiemEvent(BaseModel):
    """
    Representa un evento o log entrante desde el SIEM.
    """
    event_id: str = Field(..., description="ID único del evento en el SIEM.")
    source: str = Field(..., description="Origen del evento (ej. firewall, endpoint, web server).")
    timestamp: str = Field(..., description="Timestamp del evento.")
    event_type: str = Field(..., description="Tipo de evento o categoría (ej. login_failed, malware_detected).")
    severity: Optional[str] = Field("INFO", description="Severidad original del evento reportada por el SIEM.")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Datos crudos y adicionales del log del SIEM.")

class VulnerabilityDetail(BaseModel):
    """
    Representa un hallazgo específico de vulnerabilidad dentro de un evento.
    """
    title: str = Field(..., description="Nombre corto de la vulnerabilidad identificada.")
    severity: str = Field(..., description="Nivel de severidad asignado por el agente (ej. LOW, MEDIUM, HIGH, CRITICAL).")
    explanation: str = Field(..., description="Explicación detallada de por qué esto se considera una vulnerabilidad basada en la evidencia.")
    cve: Optional[str] = Field(None, description="CVE asociado si aplica (ej. CVE-2023-1234).")
    recommendation: Optional[str] = Field(None, description="Acción sugerida para mitigar la vulnerabilidad.")
    mitre_attack_technique: Optional[str] = Field(None, description="Codificación MITRE ATT&CK (Ej. TA0001, T1190) si es aplicable.")
    owasp_category: Optional[str] = Field(None, description="Categoría OWASP Top 10 (Ej. A03:2021-Injection) si es aplicable.")

class VulnerabilityReport(BaseModel):
    """
    Salida estructurada generada por el agente de IA tras analizar el evento.
    """
    event_id: str = Field(..., description="ID del evento que fue analizado.")
    summary: str = Field(..., description="Resumen detallado estructurado en: 1. Qué ocurrió. 2. Implicancias de seguridad. 3. Relación con MITRE/OWASP.")
    vulnerabilities_found: List[VulnerabilityDetail] = Field(default_factory=list, description="Lista de vulnerabilidades específicas encontradas.")
    is_vulnerable: bool = Field(..., description="True si se confirmó al menos una vulnerabilidad, False en caso contrario.")
    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Data cruda original que causó la alerta, adjunta para referencia.")
