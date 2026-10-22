"""Plugin registry: discovery, loading, and capability lookup.

Built-in plugins are registered explicitly. Generated plugins (from
`plugin add`, a later increment) will be discovered from a plugins directory.
The registry is the only thing the capability router talks to, so adding tools
never touches the engine.
"""
from __future__ import annotations

import shutil
from typing import Optional

from .base import Plugin
from .curl_plugin import CurlPlugin
from .feroxbuster_plugin import FeroxbusterPlugin
from .httpx_plugin import HttpxPlugin
from .nmap_plugin import NmapPlugin
from .nuclei_plugin import NucleiPlugin
from .searchsploit_plugin import SearchsploitPlugin

# Built-in one-shot plugins.
_BUILTIN_CLASSES = [NmapPlugin, CurlPlugin, FeroxbusterPlugin,
                    HttpxPlugin, NucleiPlugin, SearchsploitPlugin]


class Registry:
    def __init__(self):
        self._plugins: dict[str, Plugin] = {}
        self._capability_index: dict[str, list[str]] = {}

    @classmethod
    def with_builtins(cls, load_generated_dir: bool = True) -> "Registry":
        reg = cls()
        for klass in _BUILTIN_CLASSES:
            reg.register(klass())
        if load_generated_dir:
            reg.load_generated()
        return reg

    def load_generated(self, directory=None) -> int:
        """Load declarative adapter plugins, skipping names already registered."""
        from .. import config
        from .generated import load_generated as _load
        directory = directory or config.GENERATED_PLUGINS_DIR
        count = 0
        for plugin in _load(directory):
            if plugin.name in self._plugins:
                continue  # never let a generated spec shadow a built-in
            self.register(plugin)
            count += 1
        return count

    def register(self, plugin: Plugin) -> None:
        self._plugins[plugin.name] = plugin
        for cap in plugin.capabilities:
            self._capability_index.setdefault(cap, [])
            if plugin.name not in self._capability_index[cap]:
                self._capability_index[cap].append(plugin.name)

    def get(self, name: str) -> Optional[Plugin]:
        return self._plugins.get(name)

    def all(self) -> list[Plugin]:
        return list(self._plugins.values())

    def capabilities(self) -> dict[str, list[str]]:
        return dict(self._capability_index)

    def available_capabilities(self) -> dict[str, list[str]]:
        """Only capabilities with at least one installed/usable plugin."""
        out: dict[str, list[str]] = {}
        for cap, names in self._capability_index.items():
            avail = [n for n in names if self.is_available(self._plugins[n])]
            if avail:
                out[cap] = avail
        return out

    def is_available(self, plugin: Plugin) -> bool:
        # Delegate to the plugin so it can disambiguate its binary if needed.
        try:
            return plugin.available()
        except Exception:
            return bool(shutil.which(plugin.binary)) if plugin.binary else True

    def select(self, capability: str,
               prefer: Optional[str] = None) -> Optional[Plugin]:
        """Pick an available plugin for a capability.

        If `prefer` names a plugin that provides the capability and is available,
        use it. Otherwise return the first available provider.
        """
        names = self._capability_index.get(capability, [])
        if prefer and prefer in names:
            p = self._plugins[prefer]
            if self.is_available(p):
                return p
        for name in names:
            p = self._plugins[name]
            if self.is_available(p):
                return p
        return None
