from fastapi import APIRouter, HTTPException
from siem_agent.models.schemas import SiemEvent, VulnerabilityReport
from siem_agent.core.agent import SiemVulnerabilityAgent

router = APIRouter()

# Instanciar globalmente (idealmente mediante Inyección de Dependencias)
agent = SiemVulnerabilityAgent()

@router.post("/webhook/analyze", response_model=VulnerabilityReport, tags=["SIEM Webhook Integration"])
def analyze_log_webhook(event: SiemEvent):
    """
    Webhook genérico para recibir y analizar un log desde cualquier SIEM (push model).
    """
    try:
        # El agente orquesta el pensamiento, las tools y la extracción
        report = agent.analyze_event(event)
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analizando evento SIEM: {str(e)}")
