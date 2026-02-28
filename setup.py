from setuptools import setup, find_packages

setup(
    name="istrip",
    version="1.0.0",
    description="Advanced iPhone Tracking Stripper — strip tracking, analytics, and telemetry from iOS devices via USB",
    author="Sean-CIS",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "pymobiledevice3>=4.0.0",
        "colorama>=0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "istrip=istrip.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: Microsoft :: Windows",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
)
