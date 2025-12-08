"""Setup script for RedOps framework."""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

setup(
    name="redops",
    version="1.0.0",
    description="Advanced modular AI-assisted recon, forensics, and exposure-analysis framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="RedOps Contributors",
    url="https://github.com/AreteDriver/RedOPS",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=[
        "pydantic>=2.0.0",
    ],
    extras_require={
        "full": [
            "Pillow>=10.0.0",
            "dnspython>=2.0.0",
            "requests>=2.31.0",
            "jinja2>=3.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "redops=redops.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
