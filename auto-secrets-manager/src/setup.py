#!/usr/bin/env python3
"""
Setup script for Auto Secrets Manager Python package.
"""

from setuptools import setup, find_packages
from pathlib import Path


# Read requirements from requirements.txt
def read_requirements():
    requirements_file = Path(__file__).parent / "requirements.txt"
    if requirements_file.exists():
        with open(requirements_file, "r") as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            ]
    return []


# Read version from __init__.py
def get_version():
    init_file = Path(__file__).parent / "auto_secrets" / "__init__.py"
    if init_file.exists():
        with open(init_file, "r") as f:
            for line in f:
                if line.startswith("__version__"):
                    return line.split("=")[1].strip().strip('"').strip("'")
    return "1.0.0"


setup(
    name="auto-secrets-manager",
    version=get_version(),
    description="Automatic environment secrets management based on git branches",
    long_description="A hybrid Python/Shell solution for automatic environment secrets management with enterprise-grade security.",
    author="Auto Secrets Manager Team",
    python_requires=">=3.8",
    packages=find_packages(),
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "auto-secrets=auto_secrets.cli:main",
            "auto-secrets-daemon=auto_secrets.daemon:main",
        ]
    },
    package_data={
        "auto_secrets": [
            "shell/*.sh",
            "shell/templates/*.sh",
        ]
    },
    include_package_data=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Unix Shell",
        "Topic :: Software Development :: Build Tools",
        "Topic :: System :: Systems Administration",
        "Topic :: Security",
    ],
    keywords="secrets management devcontainer git branches environment variables",
    zip_safe=False,
)
