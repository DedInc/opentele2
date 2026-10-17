<!-- vim: syntax=Markdown -->

# opentele2

<p align="center">
<img src="https://raw.githubusercontent.com/DedInc/opentele2/main/opentele.png" alt="logo" width="180"/>
<br><br>
<a href="https://pypi.org/project/opentele2/"><img alt="pypi version" src="https://img.shields.io/pypi/v/opentele2?logo=pypi&logoColor=%232d93c1"/></a>
<a href="https://pypi.org/project/opentele2/"><img alt="pypi status" src="https://img.shields.io/pypi/status/opentele2?color=%2331c754&logo=pypi&logoColor=%232d93c1"/></a>
<a href="https://codecov.io/gh/DedInc/opentele2">
<img src="https://img.shields.io/codecov/c/github/DedInc/opentele2?color=%2331c754&label=codecov&logo=codecov&token=H2IWGEJ5LN"/>
</a>
<a href="https://github.com/DedInc/opentele2/issues"><img alt="issues" src="https://img.shields.io/github/issues/DedInc/opentele2?color=%2331c754&logo=github"/></a>
<a href="https://github.com/DedInc/opentele2/commits/main"><img alt="github last commit" src="https://img.shields.io/github/last-commit/DedInc/opentele2?color=%2331c754&logo=github"/></a>
<a href="https://github.com/DedInc/opentele2/commits/main"><img alt="github commits" src="https://img.shields.io/github/commit-activity/m/DedInc/opentele2?logo=github"/></a>
<a href="https://pypi.org/project/opentele2/"><img alt="pypi installs" src="https://img.shields.io/pypi/dm/opentele2?label=installs&logo=docusign&color=%2331c754"/></a>
<a href="https://en.wikipedia.org/wiki/MIT_License"><img alt="pypi license" src="https://img.shields.io/pypi/l/opentele2?color=%2331c754&logo=gitbook&logoColor=white"/></a>
<a href="https://github.com/psf/black"><img alt="code format" src="https://img.shields.io/badge/code%20style-black-000000.svg?logo=python&logoColor=%232d93c1"/></a>
</p>

<br>

A **Python Telegram API Library** for converting between **tdata** and **telethon** sessions, with built-in **official Telegram APIs**.

## Installation

```bash
pip install --upgrade opentele2
```

Targets **Telegram Desktop 7.3.1** tdata and **Telethon 1.45** (schema layer 230).
Telegram Desktop 7.3 protects passcode-locked tdata with Argon2id or scrypt; to
open or write Argon2id-locked tdata, install the extra:

```bash
pip install --upgrade "opentele2[argon2]"
```

## Documentation

For full documentation, guides, API reference, and examples, please visit the official documentation website:

**[https://opentele2.github.io/](https://opentele2.github.io/)**

### Quick Links

- [Getting Started](https://opentele2.github.io/)
- [Documentation & API Reference](https://opentele2.github.io/documentation)
- [Examples & Recipes](https://opentele2.github.io/examples)

## A New Era for opentele

**opentele2** is the rebirth of the original opentele project. The library is actively maintained and continues the original idea with current Telegram Desktop and Telethon support, bug fixes, and new features.

This new era means the project is no longer just a compatibility fork. It focuses on a lighter dependency footprint, pure Python internals where possible, updated official Telegram API templates, and more realistic device fingerprint generation.

### Key Enhancements

- **PyQt5 Removed**: The **PyQt5** dependency has been removed. Its required functionality was reimplemented in **pure Python** to reduce overhead and avoid installing unnecessary heavy dependencies.
- **New Fingerprints**: Device information generation has been improved. The library now uses a new device database for more realistic client profiles.
