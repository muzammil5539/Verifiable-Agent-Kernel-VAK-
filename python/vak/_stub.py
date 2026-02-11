"""Stub kernel for development when native module is not available.

All methods return sensible defaults so the Python SDK can be
used for development and testing without compiling the Rust
native module.  Build the real module with::

    maturin develop --features python
"""


class _StubKernel:
    """Stub kernel for development when native module is not available."""

    def shutdown(self) -> None:
        pass
