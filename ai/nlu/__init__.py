from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ai.nlu.explainer import explain_results
from ai.nlu.query_translator import QuerySpec, build_query, translate


@dataclass
class NLQueryResponse:
    answer: str
    needs_clarification: bool
    clarification_question: Optional[str] = None
    clarification_options: List[str] = field(default_factory=list)
    query_spec: Optional[QuerySpec] = None  # audit trail: exact resolved query
    result_count: int = 0


async def answer_question(db: AsyncSession, text: str) -> NLQueryResponse:
    """Single entry point: analyst's natural-language question in,
    evidence-grounded answer out. This is the deterministic NLU->query layer
    that sits before the conversational/LLM investigation layer — it never
    calls an LLM and never fabricates results.
    """
    translation = translate(text)

    if translation.needs_clarification or translation.query_spec is None:
        return NLQueryResponse(
            answer=translation.clarification_question or "Could you clarify your question?",
            needs_clarification=True,
            clarification_question=translation.clarification_question,
            clarification_options=translation.clarification_options,
        )

    spec = translation.query_spec
    stmt = build_query(spec)
    result = await db.execute(stmt)

    if spec.intent.value == "COUNT":
        rows: Any = [result.scalar() or 0]
    else:
        rows = result.scalars().all()

    answer = explain_results(spec, rows)
    result_count = rows[0] if spec.intent.value == "COUNT" else len(rows)

    return NLQueryResponse(
        answer=answer,
        needs_clarification=False,
        query_spec=spec,
        result_count=result_count,
    )
