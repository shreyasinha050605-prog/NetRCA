import time
import os
import openai
from sqlalchemy.orm import Session
import models

# Standard OpenAI usage - requires OPENAI_API_KEY env var
# For the prototype, we mock the LLM if the key is missing to ensure it runs.

def run_rca_analysis(incident_id: id, db: Session):
    """
    Simulated LLM call using OpenAI or a local mock.
    """
    incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
    if not incident:
        return
        
    api_key = os.getenv("OPENAI_API_KEY")
    
    if api_key:
        try:
            client = openai.OpenAI(api_key=api_key)
            prompt = f"Analyze this incident: {incident.classification} on {incident.target}. Severity: {incident.severity}. Produce a root cause, an explanation, and a detailed fix."
            
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a senior network security AI."},
                    {"role": "user", "content": prompt}
                ]
            )
            raw_text = response.choices[0].message.content
            # Very simple parser
            incident.ai_root_cause = "AI Determined Root Cause (See Details)"
            incident.ai_explanation = raw_text
            incident.ai_fix = "Implement changes according to explanation."
        except Exception as e:
            incident.ai_root_cause = "LLM Error"
            incident.ai_explanation = str(e)
            incident.ai_fix = "N/A"
    else:
        # Fallback Mock for Demo purposes
        time.sleep(2)  # Simulate network latency
        if "Misconfiguration" in incident.classification:
            incident.ai_root_cause = "Human Error - Firewall Misconfiguration"
            incident.ai_explanation = "The correlation engine detected a config change followed by instant auth failures. It appears an admin modified rule #42 which inadvertently dropped incoming VPN connections."
            incident.ai_fix = "Revert rule #42 to its previous state."
        else:
            incident.ai_root_cause = "Malicious Activity - Volumetric DDoS"
            incident.ai_explanation = "Sudden spike of packets/sec observed from multiple unique IPs targeting the payment cluster. Traffic signature matches known SYN Flood patterns."
            incident.ai_fix = "Deploy rate-limiting at the edge router and null-route offending ASNs."

    db.commit()
