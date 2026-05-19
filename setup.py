from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="willow-sdk",
    version="0.2.0",
    author="Willow",
    author_email="dev@willow.network",
    description="Python SDK for Willow - decentralized data indexing",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/willow-network/willow",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "httpx>=0.24.0",
        # Used by the light-client, consensus, and ERC-8004 modules.
        "aiohttp>=3.9.0",
        "pydantic>=2.0.0",
        # WebSocket client for GraphQL subscriptions (graphql-transport-ws).
        "websockets>=12.0",
        # `cryptography` covers both Ed25519 and secp256k1 for us. We used to
        # pull `coincurve` (libsecp256k1 wrapper) for secp256k1, but it has
        # spotty prebuilt-wheel coverage on newer Pythons (e.g. 3.14 on
        # macOS) and building from source requires a C toolchain. Using
        # `cryptography` keeps installation pure-wheel across supported
        # Python versions.
        "cryptography>=41.0.0",
        "eth-utils>=2.2.0",
        # `eth-utils.keccak` needs a keccak-256 backend at runtime;
        # pycryptodome has wide prebuilt-wheel coverage. Without this,
        # every call to `keccak(...)` raises ImportError on fresh installs.
        "eth-hash[pycryptodome]>=0.5.0",
        "python-dateutil>=2.8.0",
        "click>=8.0.0",  # For CLI
        "blake3>=0.3.0",  # For GroveDB proof verification
        # XChaCha20-Poly1305 for client-side file encryption (files.py).
        "pynacl>=1.5.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.7.0",
            "mypy>=1.4.0",
            "isort>=5.12.0",
            "flake8>=6.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "willow-cli=willow.cli:main",
        ],
    },
)