import pathlib
from setuptools import setup

README = (pathlib.Path(__file__).parent / "README.md").read_text()

PACKAGE_NAME = "opentele2"
VERSION = "1.1.0"
SOURCE_DIRECTORY = "src"

setup(
    name=PACKAGE_NAME,
    version=VERSION,
    license="MIT",
    description="A Python Telegram API Library for converting between tdata and telethon sessions, with built-in official Telegram APIs.",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/DedInc/opentele2",
    author="DedInc.",
    author_email="visitanimation@gmail.com",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Development Status :: 5 - Production/Stable",
    ],
    keywords=["tdata", "tdesktop", "telegram", "telethon", "opentele", "opentele2"],
    include_package_data=True,
    packages=[
        PACKAGE_NAME,
        PACKAGE_NAME + ".td",
        PACKAGE_NAME + ".tl",
        PACKAGE_NAME + ".devices",
    ],
    package_dir={PACKAGE_NAME: SOURCE_DIRECTORY},
    package_data={PACKAGE_NAME: ["devices/*.json"]},
    install_requires=[
        "telethon",
        "tgcrypto",
    ],
    extras_require={
        "web": ["browserforge"],
    },
)
