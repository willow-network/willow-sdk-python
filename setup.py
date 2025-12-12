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
    url="https://github.com/willow/willow-python-sdk",
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
        "pydantic>=2.0.0",
        "cryptography>=41.0.0",  # Provides Ed25519 support
        "coincurve>=18.0.0",  # secp256k1
        "eth-utils>=2.2.0",
        "python-dateutil>=2.8.0",
        "click>=8.0.0",  # For CLI
        "blake3>=0.3.0",  # For GroveDB proof verification
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