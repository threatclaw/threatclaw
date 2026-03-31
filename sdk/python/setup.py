from setuptools import setup, find_packages

setup(
    name="threatclaw-sdk",
    version="0.1.0",
    description="ThreatClaw SDK — Python client for skill development",
    author="ThreatClaw",
    license="Apache-2.0",
    packages=find_packages(),
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
    ],
)
