"""Abstract base class for all vulnerability detection modules."""

from __future__ import annotations

from abc import ABC, abstractmethod

import httpx

from models import CrawledPage, Finding


class BaseModule(ABC):
    """Each scan module analyses a crawled page and returns findings."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable module name (e.g. 'Security Headers')."""
        ...

    @abstractmethod
    async def scan(self, page: CrawledPage, client: httpx.AsyncClient) -> list[Finding]:
        """Analyse *page* and return any discovered vulnerabilities.

        The *client* can be used by active modules to make additional
        requests (e.g. injecting payloads).  Passive modules may ignore it.
        """
        ...
