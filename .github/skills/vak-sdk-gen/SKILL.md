---
name: vak-sdk-gen
description: Generate Python SDK wrapper code for VAK kernel features. Use this to help develop the future Python library.
allowed-tools: python
---

# VAK SDK Generator Skill

This skill generates boilerplate code for the Python SDK. It creates both the Rust PyO3 bindings (`src/python.rs`) and the Python wrapper class (`python/vak/__init__.py`).

## Usage

Run the `generate_wrappers.py` script with the struct name and methods you want to expose.

### Generate Wrapper

```bash
python .github/skills/vak-sdk-gen/generate_wrappers.py \
  --struct MyKernelComponent \
  --methods init_component process_data shutdown
```

## Output

The script outputs the generated code to stdout.

### Example Output

```rust
// Rust PyO3 Binding
// Add this to src/python.rs
----------------------------------------
/// Python wrapper for MyKernelComponent
#[cfg(feature = "python")]
#[pyclass(name = "MyKernelComponent")]
#[derive(Clone, Debug)]
pub struct PyMyKernelComponent {
    inner: Arc<Mutex<MyKernelComponent>>,
}

#[cfg(feature = "python")]
#[pymethods]
impl PyMyKernelComponent {
    #[new]
    fn new() -> PyResult<Self> {
        Ok(Self {
            inner: Arc::new(Mutex::new(MyKernelComponent::default())),
        })
    }

    fn init_component(&self) -> PyResult<()> {
        // TODO: Implement init_component
        let inner = self.inner.lock().unwrap();
        // inner.init_component()
        Ok(())
    }
...
}
----------------------------------------

# Python Wrapper
# Add this to python/vak/__init__.py
----------------------------------------
class MyKernelComponent:
    """Python wrapper for MyKernelComponent."""

    def __init__(self):
        self._native = _vak_native.MyKernelComponent()

    def init_component(self):
        """Wrapper for init_component."""
        return self._native.init_component()
...
----------------------------------------
```
