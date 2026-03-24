import os
import uvicorn
from fastapi import FastAPI
from dotenv import load_dotenv

# Cargar variables de entorno (ej. OPENAI_API_KEY)
load_dotenv()

from siem_agent.integrations.webhook import router as webhook_router

app = FastAPI(
    title="SIEM Vulnerability AI Agent",
    description="Agente que recibe logs de un SIEM, los analiza utilizando un LLM y reporta métricas de vulnerabilidad.",
    version="1.0.0"
)

app.include_router(webhook_router, prefix="/api/v1")

@app.get("/health", tags=["System"])
def health_check():
    """
    Endpoint para que el SIEM o un orquestador verifique que el agente está vivo.
    """
    return {"status": "ok"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
