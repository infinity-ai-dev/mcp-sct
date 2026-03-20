"""Base model provider interface and shared types."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class AnalysisRequest:
    """Request to analyze code for security issues."""
    code: str
    language: str
    file_path: str = ""
    vulnerability_type: str = ""
    rule_id: str = ""
    finding_message: str = ""
    start_line: int = 0
    end_line: int = 0
    context: dict[str, str] = field(default_factory=dict)


@dataclass
class FixSuggestion:
    """A suggested fix for a security vulnerability."""
    fixed_code: str
    explanation: str
    confidence: float
    references: list[str] = field(default_factory=list)


@dataclass
class AnalysisResponse:
    """Response from AI analysis."""
    suggestions: list[FixSuggestion]
    model_used: str = ""
    error: str = ""


SYSTEM_PROMPT = """You are a cybersecurity expert specializing in secure coding practices.
Your role is to analyze code for security vulnerabilities and provide fixes.

When given vulnerable code:
1. Identify the specific security issue
2. Explain WHY it's dangerous (attack vector, impact)
3. Provide a FIXED version of the code
4. Keep the fix minimal - only change what's necessary for security
5. Follow the language's best practices and idioms

Response format (always use this exact structure):
EXPLANATION:
<concise explanation of the vulnerability and attack vector>

FIXED_CODE:
```
<the fixed code>
```

REFERENCES:
- <relevant reference URL or standard>
"""


class ModelProvider(ABC):
    """Abstract base for LLM providers."""

    @abstractmethod
    def name(self) -> str:
        """Provider name for logging."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the provider is configured and reachable."""
        ...

    @abstractmethod
    async def analyze(self, request: AnalysisRequest) -> AnalysisResponse:
        """Analyze code and suggest fixes."""
        ...

    def _build_prompt(self, request: AnalysisRequest) -> str:
        """Build the user prompt from the analysis request."""
        parts = [f"Language: {request.language}"]

        if request.file_path:
            parts.append(f"File: {request.file_path}")

        if request.vulnerability_type:
            parts.append(f"Vulnerability type: {request.vulnerability_type}")

        if request.finding_message:
            parts.append(f"Finding: {request.finding_message}")

        if request.start_line and request.end_line:
            parts.append(f"Location: lines {request.start_line}-{request.end_line}")

        parts.append(f"\nCode to analyze:\n```{request.language}\n{request.code}\n```")

        if request.vulnerability_type:
            parts.append(
                f"\nFocus on the {request.vulnerability_type} vulnerability "
                f"and provide a secure fix."
            )
        else:
            parts.append("\nAnalyze this code for security vulnerabilities and provide fixes.")

        return "\n".join(parts)

    def _parse_response(self, text: str, model_name: str) -> AnalysisResponse:
        """Parse the structured response from the LLM."""
        explanation = ""
        fixed_code = ""
        references: list[str] = []

        # Extract EXPLANATION section
        if "EXPLANATION:" in text:
            start = text.index("EXPLANATION:") + len("EXPLANATION:")
            end = text.index("FIXED_CODE:") if "FIXED_CODE:" in text else len(text)
            explanation = text[start:end].strip()

        # Extract FIXED_CODE section
        if "FIXED_CODE:" in text:
            start = text.index("FIXED_CODE:") + len("FIXED_CODE:")
            end = text.index("REFERENCES:") if "REFERENCES:" in text else len(text)
            code_block = text[start:end].strip()
            # Extract from code fence
            if "```" in code_block:
                lines = code_block.split("\n")
                in_fence = False
                code_lines = []
                for line in lines:
                    if line.startswith("```") and not in_fence:
                        in_fence = True
                        continue
                    elif line.startswith("```") and in_fence:
                        break
                    elif in_fence:
                        code_lines.append(line)
                fixed_code = "\n".join(code_lines)
            else:
                fixed_code = code_block

        # Extract REFERENCES section
        if "REFERENCES:" in text:
            start = text.index("REFERENCES:") + len("REFERENCES:")
            ref_text = text[start:].strip()
            for line in ref_text.split("\n"):
                line = line.strip().lstrip("- ")
                if line and (line.startswith("http") or line.startswith("CWE") or line.startswith("OWASP")):
                    references.append(line)

        # Fallback: if parsing failed, use the whole response as explanation
        if not explanation and not fixed_code:
            explanation = text
            confidence = 0.3
        else:
            confidence = 0.8 if fixed_code else 0.5

        suggestion = FixSuggestion(
            fixed_code=fixed_code,
            explanation=explanation,
            confidence=confidence,
            references=references,
        )

        return AnalysisResponse(
            suggestions=[suggestion],
            model_used=model_name,
        )
