# Agente SOC impulsado por IA 🛡️🧠

Un Agente de Inteligencia Artificial diseñado para actuar como Analista de Nivel 2/Nivel 3 (L2/L3) de un Centro de Operaciones de Seguridad (SOC). Su misión principal es ingerir alertas de un SIEM (Security Information and Event Management) y determinar con alta precisión técnica si constituyen una vulnerabilidad, un ataque real o un falso positivo.

## Características Principales

Este agente toma decisiones basadas en heurística y orquestación con LLMs, utilizando herramientas integradas para enriquecer el contexto del evento:

- **Clasificador Táctico MITRE ATT&CK**: Mapea cadenas de ataque a las 14 tácticas Enterprise oficiales de MITRE, identificando la fase exacta de la *Kill Chain* (ej. Búsqueda de Credenciales, Movimiento Lateral, Evasión de Defensas).
- **Analista de Patrones Web (OWASP Top 10 2025)**: Escanea payloads en bruto buscando firmas de Inyecciones (SQL/OS), Deserialización Insegura, Path Traversal, entre otros.
- **Consultor de Vulnerabilidades (CVSS v4.0)**: Evaluación precisa de severidad técnica utilizando un registro de CVEs relevantes.
- **Inteligencia de Amenazas**: Verifica la reputación de direcciones IP para identificar Actores de Amenazas (Threat Actors) conocidos.
- **Reportes Estructurados**: Devuelve un resumen ejecutivo JSON listo para ser consumido por analistas humanos o integrarse de vuelta en un SOAR/SIEM, indicando *Qué ocurrió*, *Sus implicancias* y su *Relación con MITRE/OWASP*.

## Tecnologías Utilizadas

- **Python 3.9+**
- **FastAPI**: Servidor asíncrono y ultra rápido para la ingesta de webhooks desde el SIEM.
- **LangChain**: Framework de orquestación para el razonamiento del Agente y ejecución de herramientas (*Tool Calling*).
- **Pydantic (v2)**: Validación estricta y generación de salidas estructuradas.
- **Modelos LLM (vía OpenRouter)**: Compatible con modelos Llama 3, Mistral, Qwen, GPT-4o, etc.

---

## 🚀 Implementación y Uso

### 1. Clonar el repositorio
```bash
git clone https://github.com/asistenteainikola/AgenteSOC.git
cd AgenteSOC
```

### 2. Entorno Virtual y Dependencias
Crea un entorno virtual e instala los requerimientos básicos.
```bash
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn langchain langchain-openai pydantic
```

### 3. Configuración de Variables de Entorno
Crea un archivo `.env` en la raíz del proyecto y configura tu proveedor (ej. OpenRouter o OpenAI):
```env
OPENAI_API_KEY=tu_clave_api_aqui
OPENAI_API_BASE=https://openrouter.ai/api/v1
LLM_MODEL=meta-llama/llama-3.1-8b-instruct:free
LLM_TEMPERATURE=0.0
```
> **Nota:** Se recomienda un modelo con alta capacidad de *Tool Calling* y *Structured Output* (ej. Llama 3.1 8B, GPT-4o-mini, o Mistral).

### 4. Levantar el Servidor
```bash
uvicorn main:app --reload
```
El agente se levantará escuchando en `http://localhost:8000`.

---

## 🏛️ Consideraciones Arquitectónicas y Casos de Uso

Para garantizar un desempeño óptimo en entornos de producción, ten en cuenta las siguientes consideraciones de diseño:

1. **Copiloto, no reemplazo:** Este agente no está pensado para reemplazar a un analista de ciberseguridad humano real. Su objetivo es **apoyarlo a tomar mejores decisiones** procesando la validación heurística inicial, reduciendo el ruido y preparando un resumen estructurado con contexto accionable.
2. **Posicionamiento en la Red:** El agente **no** debe ubicarse en la primera línea de defensa (ej. ingesta cruda de Firewalls o recolectores masivos). Debido a los costos y tiempos de latencia inherentes a los LLMs, **será sobrepasado por la inmensa cantidad de eventos por segundo (EPS)**. Su lugar correcto es como un *Tier 2/3 Automático*: debe ubicarse *después* de que se hayan hecho los filtros previos (es decir, solo debe invocarse cuando el SIEM tradicional ya generó una "Alerta Notificada" por reglas de correlación).
3. **Enriquecimiento de Contexto (CTI):** Se puede potenciar drásticamente el desempeño del agente integrando fuentes adicionales de Inteligencia de Amenazas (Threat Intelligence) como herramientas. Algunas fuentes que puedes integrar para brindarle mejor contexto incluyen:
   - **Soluciones Gratuitas:** AlienVault OTX, AbuseIPDB, VirusTotal, MISP.
   - **Soluciones Comerciales (Pago):** Mandiant Advantage, CrowdStrike Falcon Intelligence, Recorded Future.
4. **Flexibilidad del Cerebro LLM:** Para lograr un mejor desempeño en tareas complejas de razonamiento o cumplir con políticas de privacidad estrictas (donde los logs no pueden salir a internet), el agente está diseñado para trabajar con diversos modelos:
   - **LLMs Locales (Privacidad y Rapidez):** Puedes configurar herramientas como Ollama o vLLM para correr modelos en la red local (ej. Llama 3 8B, Mistral, Qwen 2.5).
   - **APIs Externas (Poder de Razonamiento):** Modelos como OpenAI GPT-4o, Anthropic Claude 3.5 Sonnet o Gemini Pro 1.5 a través de servicios en la nube para analíticas que requieran un nivel cognitivo ultra alto.

---
*Desarrollado con <3 por Alfredo Randolph para potenciar la respuesta automatizada frente a incidentes cibernéticos.*
