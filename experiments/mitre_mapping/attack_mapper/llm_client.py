"""
Swappable LLM interface (Phase 4, Layer D of the HF plan). The pipeline
depends only on `LLMClient`, never on a concrete provider.

No provider is configured in this environment: no `openai`/`anthropic`
package installed, no API key, no `.env`. `NullLLMClient` is therefore the
only client actually exercised by `pipeline.py` and `validate.py` today --
`reasoner.py` treats a `NullLLMClient` as "reasoning layer skipped" and
records that explicitly in `MappedRule.processing_steps`, rather than
silently proceeding as if an LLM had reviewed the candidates.

`OpenAIClient`/`AnthropicClient` below are real adapters (not stubs) but are
untested in this environment for lack of credentials -- wire one up by
constructing it and passing it to `pipeline.AttackMapperPipeline(llm_client=...)`.
"""
from abc import ABC, abstractmethod
from typing import Optional


class LLMClient(ABC):
    @abstractmethod
    def generate(self, prompt: str, json_mode: bool = False) -> str:
        ...


class NullLLMClient(LLMClient):
    """No provider configured. `generate` is never actually called on this
    class -- callers must check `is_configured` first -- but it raises
    rather than silently returning empty output if something does call it."""

    is_configured = False

    def generate(self, prompt: str, json_mode: bool = False) -> str:
        raise RuntimeError("NullLLMClient has no backing provider; check is_configured first")


class OpenAIClient(LLMClient):
    is_configured = True

    def __init__(self, api_key: str, model: str = "gpt-4-turbo", temperature: float = 0.1):
        import openai  # local import: package not installed in this environment
        self._client = openai.OpenAI(api_key=api_key)
        self.model = model
        self.temperature = temperature

    def generate(self, prompt: str, json_mode: bool = False) -> str:
        kwargs = {"response_format": {"type": "json_object"}} if json_mode else {}
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=self.temperature,
            **kwargs,
        )
        return resp.choices[0].message.content


class AnthropicClient(LLMClient):
    is_configured = True

    def __init__(self, api_key: str, model: str = "claude-sonnet-5", temperature: float = 0.1):
        import anthropic  # local import: package not installed in this environment
        self._client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.temperature = temperature

    def generate(self, prompt: str, json_mode: bool = False) -> str:
        resp = self._client.messages.create(
            model=self.model,
            max_tokens=4096,
            temperature=self.temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        return resp.content[0].text


def default_client() -> LLMClient:
    return NullLLMClient()
