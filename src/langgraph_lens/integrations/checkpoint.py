"""Checkpoint-saver protection.

Two entry points:

  - `protect_saver(saver, lens)` — explicit per-instance wrap. Returns
    the same `saver` with its class swapped to a subclass that calls
    `lens.decide_checkpoint(...)` on every put / aput / get_tuple /
    aget_tuple. `isinstance(saver, BaseCheckpointSaver)` still holds.
  - `install_saver_auto_protection(lens)` — process-wide patch. Walks
    every existing `BaseCheckpointSaver` subclass and monkey-patches
    its methods so any user code that does
    `graph.compile(checkpointer=PostgresSaver(...))` gets inspected
    without changes.

Both paths call the same `_inspect_*` helpers, so the Tier 1 event
shape and the Tier 2 `checkpoint_protector` `block` decision look
identical regardless of which entry point is used.

Failure mode: if `langgraph` isn't importable (the lens can be used
standalone for prompt scanning or as a CLI), both calls silently
no-op and return the input unchanged.
"""

from __future__ import annotations

import contextlib
import functools
import os
from typing import TYPE_CHECKING, Any

from ..interventions import LensBlockedError

if TYPE_CHECKING:
    from ..lens import Lens


_LENS_PROTECTED_FLAG = "__langgraph_lens_protected__"


def _resolve_lens(lens: Lens | None) -> Lens | None:
    """Resolve a Lens: explicit argument wins; otherwise the global
    one installed by `install_global_callback`.
    """
    if lens is not None:
        return lens
    from ..middleware import _GLOBAL_LENS

    return _GLOBAL_LENS


def is_saver_protected(saver: Any) -> bool:
    return bool(getattr(type(saver), _LENS_PROTECTED_FLAG, False))


def protect_saver(saver: Any, lens: Lens | None = None) -> Any:
    """Wrap a `BaseCheckpointSaver` instance so the lens inspects every
    write and read. Returns the same instance with its class swapped.

    `isinstance(saver, BaseCheckpointSaver)` still holds. Any methods
    the saver added beyond the base interface are untouched.

    If `lens` is None, falls back to the global lens (set by
    `LANGGRAPH_LENS=1` or `install_global_callback`). If neither is
    available, returns the saver unchanged.
    """
    if is_saver_protected(saver):
        return saver
    resolved = _resolve_lens(lens)
    if resolved is None:
        return saver
    cls = type(saver)
    try:
        protected_cls = _build_protected_class(cls)
        # Stash the lens at the instance level so multiple savers with
        # the same class can share the patched class but use different
        # lenses if needed.
        saver.__class__ = protected_cls
        saver._lens = resolved
    except (TypeError, AttributeError):
        # Slotted class — `__class__` swap or attribute add is forbidden.
        # Fall back to patching the class in place. This affects every
        # instance of `cls` in the process, which is the same trade-off
        # `install_saver_auto_protection` makes.
        _patch_in_place(cls, resolved)
    return saver


def install_saver_auto_protection(lens: Lens | None = None) -> int:
    """Patch every currently-imported BaseCheckpointSaver subclass so
    user code that constructs them gets inspected without changes.

    Returns the count of subclasses patched (0 if langgraph isn't
    installed or auto-protection is disabled via the env var).

    Opt-out: set `LANGGRAPH_LENS_AUTO_PROTECT=0` in the environment.
    """
    if os.environ.get("LANGGRAPH_LENS_AUTO_PROTECT") == "0":
        return 0
    resolved = _resolve_lens(lens)
    if resolved is None:
        return 0
    try:
        from langgraph.checkpoint.base import BaseCheckpointSaver
    except ImportError:
        return 0

    patched = 0
    # Walk the full subclass tree (subclasses of subclasses).
    seen: set[type] = set()
    stack: list[type] = [BaseCheckpointSaver]
    while stack:
        cls = stack.pop()
        if cls in seen:
            continue
        seen.add(cls)
        stack.extend(cls.__subclasses__())
        if cls is BaseCheckpointSaver:
            continue  # the abstract base itself has nothing to patch
        if getattr(cls, _LENS_PROTECTED_FLAG, False):
            continue
        _patch_in_place(cls, resolved)
        patched += 1

    # Hook __init_subclass__ on the base so subclasses defined AFTER
    # this point (e.g. user-imports of a checkpoint package that
    # hasn't loaded yet) also get protected.
    _install_subclass_hook(BaseCheckpointSaver, resolved)

    return patched


# ---------------------------------------------------------------------------
# Internal: build a protected subclass / patch in place
# ---------------------------------------------------------------------------


def _build_protected_class(cls: Any) -> type:
    """Return a dynamically-created subclass of `cls` with put / aput /
    get_tuple / aget_tuple overridden to call the lens.
    """
    cached_attr = "__langgraph_lens_protected_subclass__"
    cached = cls.__dict__.get(cached_attr)
    if cached is not None:
        return cached  # type: ignore[no-any-return]

    name = f"Lens{cls.__name__}"
    namespace = {
        "put": _make_protected_put(cls.put),
        "aput": _make_protected_aput(cls.aput),
        "get_tuple": _make_protected_get(cls.get_tuple),
        "aget_tuple": _make_protected_aget(cls.aget_tuple),
        _LENS_PROTECTED_FLAG: True,
    }
    protected = type(name, (cls,), namespace)
    # Cache so repeated `protect_saver` calls on instances of the same
    # class don't proliferate identical classes. Some classes (slotted,
    # certain C-extensions) can't accept new attributes — caching is
    # an optimisation, not a correctness requirement, so just skip.
    with contextlib.suppress(AttributeError, TypeError):
        setattr(cls, cached_attr, protected)
    return protected


def _patch_in_place(cls: Any, lens: Lens) -> None:
    """Patch `cls.put` / `aput` / `get_tuple` / `aget_tuple` in place.
    Used by `install_saver_auto_protection`.
    """
    cls.put = _make_protected_put(cls.put)
    cls.aput = _make_protected_aput(cls.aput)
    cls.get_tuple = _make_protected_get(cls.get_tuple)
    cls.aget_tuple = _make_protected_aget(cls.aget_tuple)
    setattr(cls, _LENS_PROTECTED_FLAG, True)


def _install_subclass_hook(base: Any, lens: Lens) -> None:
    """Make sure subclasses created after this point are auto-patched."""
    if getattr(base, "__langgraph_lens_subclass_hook_installed__", False):
        return
    original_init_subclass = base.__init_subclass__

    def __init_subclass__(cls: Any, /, **kwargs: Any) -> None:  # noqa: N807
        original_init_subclass(**kwargs)
        if not getattr(cls, _LENS_PROTECTED_FLAG, False):
            _patch_in_place(cls, lens)

    # `__init_subclass__` is implicitly a classmethod
    base.__init_subclass__ = classmethod(__init_subclass__)
    base.__langgraph_lens_subclass_hook_installed__ = True


# ---------------------------------------------------------------------------
# Method wrappers
# ---------------------------------------------------------------------------


def _thread_id_from_config(config: Any) -> str | None:
    if not isinstance(config, dict):
        return None
    configurable = config.get("configurable") or {}
    if not isinstance(configurable, dict):
        return None
    tid = configurable.get("thread_id")
    return tid if isinstance(tid, str) else None


def _checkpoint_id_from_config(config: Any) -> str | None:
    if not isinstance(config, dict):
        return None
    configurable = config.get("configurable") or {}
    if not isinstance(configurable, dict):
        return None
    cid = configurable.get("checkpoint_id")
    return cid if isinstance(cid, str) else None


def _make_protected_put(original: Any) -> Any:
    @functools.wraps(original)
    def put(self: Any, config: Any, checkpoint: Any, metadata: Any, *args: Any, **kwargs: Any) -> Any:
        lens = getattr(self, "_lens", None)
        if lens is None:
            from ..middleware import _GLOBAL_LENS as _GL

            lens = _GL
        if lens is not None:
            decision, _event = lens.decide_checkpoint(
                blob=checkpoint,
                metadata=metadata if isinstance(metadata, dict) else {},
                thread_id=_thread_id_from_config(config),
                checkpoint_id=_checkpoint_id_from_config(config),
                direction="write",
            )
            if decision.is_terminal:
                raise LensBlockedError(decision)
        return original(self, config, checkpoint, metadata, *args, **kwargs)

    return put


def _make_protected_aput(original: Any) -> Any:
    @functools.wraps(original)
    async def aput(
        self: Any, config: Any, checkpoint: Any, metadata: Any, *args: Any, **kwargs: Any
    ) -> Any:
        lens = getattr(self, "_lens", None)
        if lens is None:
            from ..middleware import _GLOBAL_LENS as _GL

            lens = _GL
        if lens is not None:
            decision, _event = lens.decide_checkpoint(
                blob=checkpoint,
                metadata=metadata if isinstance(metadata, dict) else {},
                thread_id=_thread_id_from_config(config),
                checkpoint_id=_checkpoint_id_from_config(config),
                direction="write",
            )
            if decision.is_terminal:
                raise LensBlockedError(decision)
        return await original(self, config, checkpoint, metadata, *args, **kwargs)

    return aput


def _make_protected_get(original: Any) -> Any:
    @functools.wraps(original)
    def get_tuple(self: Any, config: Any, *args: Any, **kwargs: Any) -> Any:
        result = original(self, config, *args, **kwargs)
        lens = getattr(self, "_lens", None)
        if lens is None:
            from ..middleware import _GLOBAL_LENS as _GL

            lens = _GL
        if lens is not None and result is not None:
            blob = _extract_blob_from_tuple(result)
            if blob is not None:
                decision, _event = lens.decide_checkpoint(
                    blob=blob,
                    metadata=_extract_metadata_from_tuple(result),
                    thread_id=_thread_id_from_config(config),
                    checkpoint_id=_checkpoint_id_from_config(config),
                    direction="read",
                )
                if decision.is_terminal:
                    raise LensBlockedError(decision)
        return result

    return get_tuple


def _make_protected_aget(original: Any) -> Any:
    @functools.wraps(original)
    async def aget_tuple(self: Any, config: Any, *args: Any, **kwargs: Any) -> Any:
        result = await original(self, config, *args, **kwargs)
        lens = getattr(self, "_lens", None)
        if lens is None:
            from ..middleware import _GLOBAL_LENS as _GL

            lens = _GL
        if lens is not None and result is not None:
            blob = _extract_blob_from_tuple(result)
            if blob is not None:
                decision, _event = lens.decide_checkpoint(
                    blob=blob,
                    metadata=_extract_metadata_from_tuple(result),
                    thread_id=_thread_id_from_config(config),
                    checkpoint_id=_checkpoint_id_from_config(config),
                    direction="read",
                )
                if decision.is_terminal:
                    raise LensBlockedError(decision)
        return result

    return aget_tuple


def _extract_blob_from_tuple(tup: Any) -> Any:
    """`CheckpointTuple.checkpoint` is what we want to scan. Tolerate
    callers that return a raw dict or bytes too.
    """
    cp = getattr(tup, "checkpoint", None)
    if cp is not None:
        return cp
    if isinstance(tup, (dict, bytes, bytearray)):
        return tup
    return None


def _extract_metadata_from_tuple(tup: Any) -> dict[str, Any]:
    md = getattr(tup, "metadata", None)
    return md if isinstance(md, dict) else {}
