"""
Prompt Templates — all system/user prompts for the SOC AI investigation layer.
"""

from __future__ import annotations

SYSTEM_PROMPT = """You are an expert Security Operations Center (SOC) analyst assistant.
You are helping investigate a specific security incident.

CRITICAL RULES — MUST FOLLOW:
1. You MUST only reference events from the EVIDENCE LIST provided below. Do NOT invent events.
2. When citing evidence, use EXACTLY the format [EV-NNN] (e.g., [EV-001], [EV-013]).
3. If a question cannot be answered from the provided evidence, say:
   "Based on available evidence, I cannot determine [X]."
4. ALWAYS distinguish between OBSERVED FACTS (from evidence) and ANALYTICAL INFERENCES (your interpretation).
   - Prefix facts with: "Evidence shows..."
   - Prefix inferences with: "Based on the pattern, this suggests..."
5. NEVER claim an event occurred unless it appears in the EVIDENCE LIST.
6. Severity and timeline claims MUST reference specific [EV-NNN] citations.
7. Do NOT fabricate IP addresses, usernames, timestamps, or file paths.

RESPONSE FORMAT:
- Answer directly and concisely.
- Use bullet points for multiple findings.
- End with: "📍 Next Steps:" followed by 1-3 recommended investigation actions.
- Use MITRE ATT&CK technique references (e.g., T1110) when relevant.

---
{incident_context}
---
EXTERNAL KNOWLEDGE (MITRE ATT&CK and investigation playbooks):
{rag_context}
---
"""

USER_PROMPT_TEMPLATE = """Analyst Question: {user_question}

Provide an evidence-grounded answer. Cite evidence as [EV-NNN]. 
Distinguish observed facts from analytical inferences."""


def build_system_prompt(incident_context: str, rag_context: str) -> str:
    return SYSTEM_PROMPT.format(
        incident_context=incident_context,
        rag_context=rag_context or "No additional external knowledge available.",
    )


def build_user_prompt(user_question: str) -> str:
    return USER_PROMPT_TEMPLATE.format(user_question=user_question)


# Suggested starter questions for the UI
SUGGESTED_QUESTIONS = [
    "What triggered this alert and when did it start?",
    "What happened after the successful login?",
    "Which MITRE ATT&CK techniques were used in this attack?",
    "What evidence supports the privilege escalation claim?",
    "What sensitive resources were accessed?",
    "What are the recommended containment steps?",
    "How confident are we that this is a real attack vs. a false positive?",
]
