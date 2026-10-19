"""1.5.0 ``src/td``: Telegram Desktop folders and their accounts and keys,
read and written by :mod:`opentele2._native`."""

from __future__ import annotations

from .account import Account as Account
from .auth import AuthKey as AuthKey
from .auth import AuthKeyType as AuthKeyType
from .tdesktop import TDesktop as TDesktop

__all__ = ["Account", "AuthKey", "AuthKeyType", "TDesktop"]
