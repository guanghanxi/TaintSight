import json
import os
import threading
from typing import Dict, Any, Type, Optional
import hashlib

import httpx
from dotenv import load_dotenv, find_dotenv
load_dotenv(find_dotenv())

from langchain_qwq import ChatQwen
from langchain_deepseek import ChatDeepSeek
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_core.language_models import BaseChatModel
from langchain_core.runnables import RunnableConfig

class LLMClientManager:
    def __init__(self):
        self._provider_configs: Dict[str, Dict[str, Any]] = {
            "deepseek": {
                "class": ChatDeepSeek,
                "url_param": "base_url",
                "default_url": "https://api.deepseek.com",
                "key_param": "api_key",
                "key_env": "DEEPSEEK_API_KEY",
            },
            "qwen": {
                "class": ChatQwen,
                "url_param": "base_url",
                "default_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
                "key_param": "api_key",
                "key_env": "DASHSCOPE_API_KEY",         # as used by langchain_qwq
            },
            "openai": {
                "class": ChatOpenAI,
                "url_param": "base_url",
                "default_url": os.getenv("OPENAI_PROXY_URL", "https://api.your-proxy.com/v1"),
                "key_param": "api_key",
                "key_env": "OPENAI_API_KEY",
                # Client defaults applied only to this provider entry.
                # Keeping retries in our own layer makes every failed attempt
                # visible to fallback handling and auditing.
                "default_kwargs": {
                    # connect 5s: matches the OpenAI SDK default. Keep it small:
                    #   without public DNS getaddrinfo() can hang for >20s, so an
                    #   unreachable proxy would otherwise burn the read timeout.
                    # read 240s: generous headroom over realistic analyzer requests.
                    # write 30s / pool 10s: request bodies are small.
                    "timeout": httpx.Timeout(connect=5.0, read=240.0, write=30.0, pool=10.0),
                    # Disable the SDK's hidden retries so the real attempt count
                    # is what we log; Retry-After is honored by retry_policy
                    # instead (capped at 120s).
                    "max_retries": 0,
                    # Use the /v1/responses endpoint so tool calls and reasoning
                    # can coexist; on chat/completions they are mutually exclusive.
                    # Note that _llm_type stays 'openai-chat' with this flag, so the
                    # endpoint must be detected from instance attributes; see
                    # retry_policy.bind_tools_compat.
                    "use_responses_api": True,
                    # The default output_version "responses/v1" puts reasoning
                    # blocks (including a large encrypted_content base64 string)
                    # inside AIMessage.content, which bloats history and breaks
                    # prompt rendering. "v0" restores the plain form: content is
                    # a list of {"type":"text"} blocks and reasoning moves to
                    # additional_kwargs["reasoning"]. Content remains a list,
                    # which estimate_message_tokens and _extract_code_block
                    # already handle.
                    "output_version": "v0",
                    # Pin the reasoning effort so the relay cannot silently
                    # change it; xhigh maps to the provider default high on
                    # DeepSeek-compatible endpoints and is a no-op there.
                    "reasoning_effort": "xhigh",

                    # Pin the sampling temperature; the server default is also 1.
                    "temperature": 1,

                    # Explicit output cap, aligned with the 64K thinking-mode
                    # default of DeepSeek-compatible APIs. Leaving
                    # max_output_tokens unset means "no cap" on this endpoint.
                    # langchain renames max_tokens to max_output_tokens.
                    "max_tokens": 65536,
                },
            },
            "zai": {
                "class": ChatOpenAI,
                "url_param": "base_url",
                "default_url": "https://open.bigmodel.cn/api/paas/v4/",
                "key_param": "api_key",
                "key_env": "ZAI_API_KEY",
            },
            "anthropic": {
                "class": ChatAnthropic,
                "url_param": "anthropic_api_url",
                "default_url": os.getenv("ANTHROPIC_PROXY_URL", "https://api.your-proxy.com/anthropic"),
                "key_param": "api_key",
                "key_env": "ANTHROPIC_API_KEY",
            },
        }
        self._cache: Dict[str, BaseChatModel] = {}
        self._lock = threading.Lock()

    def _generate_cache_key(self, provider: str, model: str, kwargs: Dict[str, Any]) -> str:
        serializable = {}
        for k, v in kwargs.items():
            if not isinstance(v, (str, int, float, bool, list, dict, type(None))):
                continue
            # Keep only a fingerprint of sensitive fields, never plaintext
            if "key" in k.lower() or "token" in k.lower():
                serializable[k] = f"<sha:{hashlib.sha256(str(v).encode()).hexdigest()[:8]}>"
            else:
                serializable[k] = v
        return f"{provider}::{model}::{json.dumps(serializable, sort_keys=True)}"

    def get_llm(self, provider: str, model: str, **kwargs) -> BaseChatModel:
        provider = provider.lower()
        if provider not in self._provider_configs:
            raise ValueError(f"Unsupported provider: {provider}. Supported: {list(self._provider_configs.keys())}")

        config = self._provider_configs[provider]
        model_class = config["class"]

        # 1. URL injection: explicit kwargs > default URL
        url_param = config["url_param"]
        if url_param not in kwargs and config["default_url"]:
            kwargs[url_param] = config["default_url"]

        # 2. API key injection: explicit kwargs > env var > explicit error
        key_param = config.get("key_param", "api_key")
        if key_param not in kwargs:
            env_key = os.getenv(config["key_env"]) if config.get("key_env") else None
            if env_key:
                kwargs[key_param] = env_key
            elif not config.get("key_optional", False):
                raise ValueError(
                    f"[{provider}] Missing API key: pass '{key_param}' in the model config "
                    f"or set the {config.get('key_env')} environment variable"
                )

        # 3. Provider default kwargs: explicit kwargs > provider defaults.
        #    Same precedence as URL/key injection; providers without defaults are unchanged.
        for k, v in (config.get("default_kwargs") or {}).items():
            kwargs.setdefault(k, v)

        cache_key = self._generate_cache_key(provider, model, kwargs)
        if cache_key not in self._cache:
            with self._lock:
                if cache_key not in self._cache:
                    instance = model_class(model=model, **kwargs)
                    self._cache[cache_key] = instance
        return self._cache[cache_key]

    def get_llm_from_dict(self, model_info: Dict[str, Any]) -> BaseChatModel:
        """Convenience method: get an LLM from a dict."""
        info = model_info.copy()
        provider = info.pop("provider")
        model = info.pop("model")
        return self.get_llm(provider=provider, model=model, **info)

    def clear_cache(self):
        """Clear the cache."""
        with self._lock:
            self._cache.clear()

# Global singleton
llm_manager = LLMClientManager()

def get_llm_based_on_config(config: RunnableConfig):
    configurable = config.get("configurable", {}) if config else {}
    model_config = configurable.get("target_model_config", {
        "provider": "deepseek", 
        "model": "deepseek-flash"
    })
    return llm_manager.get_llm_from_dict(model_config)

def get_llm_based_on_simple_config(model_config: Optional[Dict[str, Any]] = None) -> BaseChatModel:
    """
    Build an LLM instance from a simple model-config dict.

    Useful for callers outside LangGraph nodes (pipeline orchestration,
    standalone scripts) that do not want to wrap the config in a nested
    LangChain RunnableConfig.

    Args:
        model_config: dict with provider, model, etc. Uses defaults if None.
    """
    if model_config is None:
        model_config = {
            "provider": "deepseek",
            "model": "deepseek-flash"
        }
    return llm_manager.get_llm_from_dict(model_config)