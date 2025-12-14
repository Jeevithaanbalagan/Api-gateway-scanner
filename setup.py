from setuptools import setup

setup(
    name="api-gateway-scanner",
    version="1.0.0",
    py_modules=["cli"],
    install_requires=[
        "click",
        "httpx",
        "pyyaml",
        "jinja2",
        "reportlab",
        "python-docx"
    ],
    entry_points={
        "console_scripts": [
            "ags=cli:cli"
        ]
    },
)
