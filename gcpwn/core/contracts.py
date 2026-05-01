from __future__ import annotations

from typing import Any, Iterable


class HashableResourceProxy:
    """
    Small reusable wrapper for SDK objects that need to be:
    - hashable in sets
    - optionally marked as validated/not yet validated
    - transparently proxied for attribute access
    """

    def __init__(
        self,
        resource: Any,
        *,
        key_fields: Iterable[str],
        validated: bool = True,
        repr_fields: Iterable[str] | None = None,
    ) -> None:
        self._resource = resource
        self.validated = validated
        self._key_fields = tuple(key_fields)
        self._repr_fields = tuple(repr_fields or self._key_fields)

    def _key(self) -> tuple[Any, ...]:
        return tuple(self._resource_value(field) for field in self._key_fields)

    def _resource_value(self, field: str) -> Any:
        resource = self._resource
        if isinstance(resource, dict):
            return resource.get(field)
        return getattr(resource, field, None)

    def __hash__(self) -> int:
        return hash(self._key())

    def __eq__(self, other: object) -> bool:
        return isinstance(other, HashableResourceProxy) and self._key() == other._key()

    def __getattr__(self, attr: str) -> Any:
        return self._resource_value(attr)

    def __repr__(self) -> str:
        values = ", ".join(f"{field}={self._resource_value(field)}" for field in self._repr_fields)
        return f"{self.__class__.__name__}({values})"
