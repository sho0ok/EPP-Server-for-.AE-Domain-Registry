"""
EPP Client Toolkit Setup
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="epp-client",
    version="1.0.0",
    author="AE Registry",
    author_email="registry@ae",
    description="EPP Client Toolkit for Domain Registrars",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/sho0ok/EPP-Client-Toolkit",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet :: Name Service (DNS)",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.9",
    install_requires=[
        "lxml>=4.9.0",
        "pyyaml>=6.0",
        "click>=8.0.0",
        "python-dateutil>=2.8.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "types-PyYAML",
            "types-python-dateutil",
        ],
    },
    entry_points={
        "console_scripts": [
            "epp=epp_cli.main:main",
        ],
    },
)
