"""Ask Pramaan: a plain-language assistant grounded only in the case data the signed-in user may see.

It explains findings, proof levels and next steps, cites findings as [F<id>], and never recommends a decision:
AI flags, officers decide. Needs ANTHROPIC_API_KEY (or another Anthropic credential) on the server.
"""
import json

import anthropic

MODEL = "claude-opus-5-5"
SYSTEM = """You are Ask Pramaan, the assistant inside Pramaan, AICTE's pre-scrutiny tool for technical-college approvals.

You answer questions about the case data given to you in <case_data>. Rules:
- Use only <case_data>. If the answer is not there, say "That is not in the record" and say what would answer it.
- Cite findings as [F<id>] (for example [F3]) and quote the APH clause they cite when relevant.
- Plain words for officers, college staff, students and parents. Short paragraphs or short bullet lists. No jargon; if a
  technical term is unavoidable, explain it in one clause.
- Never recommend approving, rejecting or penalising a college. Decisions belong to AICTE officers. You may explain what a
  finding means, how strong the evidence is, what the college can do to fix it, and what an officer might check next.
- A finding is a preliminary indicator, not proof of fraud. Say so when someone treats it as proof.
- If the user is a college (role "institution"), help them understand and fix their own application; you have no data
  about other colleges and must not guess about them.
- Answer in the language the user writes in (English or Hindi)."""


def case_context(app, run, decision, record):
    """What the assistant may see for one application: the run, proof levels, changes and decision, in compact form."""
    if not run:
        return {"application": app, "checks": "not run yet"}
    return {
        "application": {k: app[k] for k in ("id", "institution", "aicte_id", "category", "status", "proposed_intake",
                                            "faculty_count", "classroom_areas_sqm", "building_age_years")},
        "rules_version": run["rules_version"], "recommendation": run["outcome"], "risk_score": run["risk_score"],
        "findings": [{"id": f["id"], "title": f["title"], "severity": f["severity"], "message": f["message"],
                      "clause": f["clause"], "suggested_next_step": f["action"], "review": f["status"],
                      "reviewed_by": f.get("reviewed_by"), "review_reason": f.get("review_reason")} for f in run["findings"]],
        "proof": {"score": run["proof"]["score"], "independently_confirmed_pct": run["proof"]["independent_pct"],
                  "claims": run["proof"]["claims"]},
        "changes_since_last_approval": run["changes"],
        "issuer_checks": [{"document": v["doc"], "source": v["source"], "status": v["status"]} for v in run["verifications"]],
        "photos": run["photos"],
        "decision": decision, "approval_record": record and {"id": record["id"], "issued_at": record["issued_at"]},
    }


def queue_context(apps):
    """Queue-level view for questions like "what needs attention today?"."""
    return {"queue": [{k: a.get(k) for k in ("id", "institution", "category", "status", "outcome", "risk_score",
                                             "open_findings", "decision")} for a in apps]}


def ask(question, history, context, role):
    """One grounded answer. Raises anthropic errors; the API layer turns them into HTTP errors."""
    client = anthropic.Anthropic()
    messages = [*history[-10:], {"role": "user", "content": question}]  # last 5 exchanges is plenty for a case chat
    response = client.beta.messages.create(
        model=MODEL,
        max_tokens=4000,
        system=[{"type": "text", "text": SYSTEM},
                {"type": "text", "text": f"<role>{role}</role>\n<case_data>{json.dumps(context, ensure_ascii=False)}</case_data>",
                 "cache_control": {"type": "ephemeral"}}],  # case data is stable across a conversation, so cache it
        messages=messages,
        output_config={"effort": "low"},  # short grounded chat answers; low effort keeps them fast
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",  # if a safety classifier declines, the API retries on a fallback model in the same call
    )
    if response.stop_reason == "refusal":
        return "I can't answer that one. Ask about the findings, the evidence or what the college can fix."
    return "".join(b.text for b in response.content if b.type == "text").strip()
