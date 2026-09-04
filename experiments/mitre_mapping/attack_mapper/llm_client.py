"""
Swappable LLM interface (Phase 4, Layer D of the HF plan). The pipeline
depends only on `LLMClient`, never on a concrete provider.

`NullLLMClient` is the default -- `reasoner.py` treats it as "reasoning
layer skipped" and records that explicitly in `MappedRule.processing_steps`,
rather than silently proceeding as if an LLM had reviewed the candidates.

Three ways to actually configure one, in increasing order of setup cost:

1. **Local, free** -- `ollama_client()` below, talking to Ollama's
   OpenAI-compatible endpoint. See `../LLM_SETUP.md` for install/model-pull
   instructions. No API key, no per-call cost, nothing added to this repo
   (model weights live in Ollama's own cache, e.g.
   `C:\\Users\\<you>\\.ollama\\models` on Windows -- never commit those).
2. `OpenAIClient(api_key=...)` -- hosted OpenAI, or any other
   OpenAI-API-compatible provider via `base_url`.
3. `AnthropicClient(api_key=...)` -- hosted Anthropic.

Wire any of them up by constructing it and passing it to
`pipeline.AttackMapperPipeline(llm_client=...)`.
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
    """Hosted OpenAI by default. Pass `base_url` to point at any other
    OpenAI-API-compatible server instead (Ollama, Azure OpenAI, vLLM, ...)
    -- see `ollama_client()` below for the local case."""

    is_configured = True

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4-turbo",
        temperature: float = 0.1,
        base_url: Optional[str] = None,
    ):
        import openai  # local import: package not installed in this environment
        self._client = openai.OpenAI(api_key=api_key, base_url=base_url)
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


def ollama_client(
    model: str = "llama3.2:3b",
    base_url: str = "http://localhost:11434/v1",
    temperature: float = 0.1,
) -> OpenAIClient:
    """Convenience factory for a local Ollama server -- see ../LLM_SETUP.md
    for install/model-pull steps. Ollama exposes an OpenAI-compatible
    endpoint, so this is just `OpenAIClient` pointed at localhost with a
    placeholder API key (Ollama doesn't check it, but the openai SDK
    requires a non-empty string).

    Default model is the small one (~2GB): the only one actually scored so
    far (33.8% top-1, a regression from the 53.8% LLM-off baseline -- see
    findings.md's "LLM layer tested" section) and the only one that doesn't
    risk an out-of-memory kill on a modest machine. `llama3.1:8b` repeatedly
    triggered OOM kills here before finishing a run; pass a bigger `model`
    only if you have the headroom to spare."""
    return OpenAIClient(api_key="ollama", model=model, base_url=base_url, temperature=temperature)
