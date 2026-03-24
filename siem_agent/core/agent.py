import os
import json
from langchain_openai import ChatOpenAI
from langchain.agents import create_tool_calling_agent, AgentExecutor
from siem_agent.core.prompts import get_agent_prompt
from siem_agent.core.skills import AGENT_TOOLS
from siem_agent.models.schemas import SiemEvent, VulnerabilityReport

class SiemVulnerabilityAgent:
    def __init__(self):
        # Configuramos el LLM por defecto de OpenAI
        # (Esto podría abstraerse para soportar otros LLMs en el futuro)
        llm_model = os.getenv("LLM_MODEL", "qwen/qwen3.5-9b") # default openrouter model
        temperature = float(os.getenv("LLM_TEMPERATURE", "0.0"))
        base_url = os.getenv("OPENAI_API_BASE", "https://openrouter.ai/api/v1")
        api_key = os.getenv("OPENAI_API_KEY")
        
        self.llm = ChatOpenAI(
            model=llm_model, 
            temperature=temperature, 
            openai_api_base=base_url,
            openai_api_key=api_key
        )
        
        # 1. Configurar el Agente con Tools para investigar
        prompt = get_agent_prompt()
        self.agent = create_tool_calling_agent(self.llm, AGENT_TOOLS, prompt)
        self.agent_executor = AgentExecutor(agent=self.agent, tools=AGENT_TOOLS, verbose=True)
        
        # 2. Configurar una versión del LLM para estructurar la salida final en Pydantic
        self.structured_llm = self.llm.with_structured_output(VulnerabilityReport)

    def analyze_event(self, event: SiemEvent) -> VulnerabilityReport:
        """
        Analiza un log del SIEM utilizando el LLM y sus tools, luego devuelve un reporte estructurado.
        """
        event_str = event.model_dump_json(indent=2)
        
        # Paso 1: El agente razona y usa herramientas
        response = self.agent_executor.invoke({
            "input": f"Analiza este evento SIEM detalladamente. Usa tus herramientas para buscar reputación de IPs o información de CVEs si están presentes. Evento a analizar:\n{event_str}"
        })
        
        analysis_text = response.get("output", "")
        
        # Paso 2: Extraer de manera estructurada usando pydantic based generation
        extraction_prompt = f"""
        Basado en tu análisis experto, genera el reporte final de vulnerabilidades extraído en JSON.
        IMPORTANTE: El campo 'summary' DEBE estructurarse indicando claramente:
        1. Qué ocurrió.
        2. Qué implicancias tiene para la seguridad.
        3. Su Relación con tácticas/técnicas de MITRE ATT&CK y/o patrones del OWASP Top 10.
        
        Data Original del SIEM:
        {event_str}
        
        Tu Análisis (Razonamiento del Agente):
        {analysis_text}
        """
        
        final_report = self.structured_llm.invoke(extraction_prompt)
        # Nos aseguramos de adjuntar la raw_data original
        final_report.raw_data = event.model_dump() 
        return final_report
