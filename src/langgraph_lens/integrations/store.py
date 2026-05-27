"""BaseStore protection — auto-fire `lens.inspect_memory_write` on
every `put` / `aput` call.

Same two-entry-point shape as the saver protector:

  - `protect_store(store, lens)` — explicit per-instance wrap.
  - `install_store_auto_protection(lens)` — process-wide patch
    walking every existing `BaseStore` subclass.

The store's other methods (get / search / list_namespaces / etc.)
are left alone — memory-poisoning detection is a write-time concern.
"""

from __future__ import annotations

import functools
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..lens import Lens


_LENS_PROTECTED_FLAG = "__langgraph_lens_store_protected__"


def _resolve_lens(lens: Lens | None) -> Lens | None:
    if lens is not None:
        return lens
    from ..middleware import _GLOBAL_LENS

    return _GLOBAL_LENS


def is_store_protected(store: Any) -> bool:
    return bool(getattr(type(store), _LENS_PROTECTED_FLAG, False))


def protect_store(store: Any, lens: Lens | None = None) -> Any:
    if is_store_protected(store):
        return store
    resolved = _resolve_lens(lens)
    if resolved is None:
        return store
    cls = type(store)
    try:
        namespace = {
            "put": _make_protected_put(cls.put),
            "aput": _make_protected_aput(cls.aput),
            _LENS_PROTECTED_FLAG: True,
        }
        protected_cls = type(f"Lens{cls.__name__}", (cls,), namespace)
        store.__class__ = protected_cls
        store._lens = resolved
    except (TypeError, AttributeError):
        # InMemoryStore and friends use __slots__ — `__class__` swap and
        # attribute addition are both forbidden. Patch the class in place
        # instead; same trade-off `install_store_auto_protection` makes.
        _patch_in_place(cls)
    return store


def install_store_auto_protection(lens: Lens | None = None) -> int:
    if os.environ.get("LANGGRAPH_LENS_AUTO_PROTECT") == "0":
        return 0
    resolved = _resolve_lens(lens)
    if resolved is None:
        return 0
    try:
        from langgraph.store.base import BaseStore
    except ImportError:
        return 0

    patched = 0
    seen: set[type] = set()
    stack: list[type] = [BaseStore]
    while stack:
        cls = stack.pop()
        if cls in seen:
            continue
        seen.add(cls)
        stack.extend(cls.__subclasses__())
        if cls is BaseStore:
            continue
        if getattr(cls, _LENS_PROTECTED_FLAG, False):
            continue
        _patch_in_place(cls)
        patched += 1

    _install_subclass_hook(BaseStore)

    return patched


def _patch_in_place(cls: Any) -> None:
    cls.put = _make_protected_put(cls.put)
    cls.aput = _make_protected_aput(cls.aput)
    setattr(cls, _LENS_PROTECTED_FLAG, True)


def _install_subclass_hook(base: Any) -> None:
    if getattr(base, "__langgraph_lens_store_subclass_hook_installed__", False):
        return
    original_init_subclass = base.__init_subclass__

    def __init_subclass__(cls: Any, /, **kwargs: Any) -> None:  # noqa: N807
        original_init_subclass(**kwargs)
        if not getattr(cls, _LENS_PROTECTED_FLAG, False):
            _patch_in_place(cls)

    base.__init_subclass__ = classmethod(__init_subclass__)
    base.__langgraph_lens_store_subclass_hook_installed__ = True


def _key_for(namespace: Any, key: str) -> str:
    if isinstance(namespace, (tuple, list)):
        return "/".join([str(p) for p in namespace] + [str(key)])
    return f"{namespace}/{key}"


def _make_protected_put(original: Any) -> Any:
    @functools.wraps(original)
    def put(
        self: Any,
        namespace: Any,
        key: str,
        value: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        lens = getattr(self, "_lens", None)
        if lens is None:
            from ..middleware import _GLOBAL_LENS as _GL

            lens = _GL
        if lens is not None:
            lens.inspect_memory_write(key=_key_for(namespace, key), value=value)
        return original(self, namespace, key, value, *args, **kwargs)

    return put


def _make_protected_aput(original: Any) -> Any:
    @functools.wraps(original)
    async def aput(
        self: Any,
        namespace: Any,
        key: str,
        value: Any,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        lens = getattr(self, "_lens", None)
        if lens is None:
            from ..middleware import _GLOBAL_LENS as _GL

            lens = _GL
        if lens is not None:
            lens.inspect_memory_write(key=_key_for(namespace, key), value=value)
        return await original(self, namespace, key, value, *args, **kwargs)

    return aput
