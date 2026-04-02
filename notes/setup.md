# Installing liboqs-python
The repository of interest is https://github.com/open-quantum-safe/liboqs-python.

We follow the simple steps from the section **Let liboqs-python install liboqs automatically**

Here's the summary of the steps:
-  Install and activate a Python virtual environment
    ```bash
    python3 -m venv venv
    . venv/bin/activate
    python3 -m ensurepip --upgrade
    ```

- Configure and install the wrapper
    ```bash
    git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
    cd liboqs-python
    pip install .
    ```
- Run the examples
    ```bash
    python3 liboqs-python/examples/kem.py
    python3 liboqs-python/examples/sig.py
    ```
