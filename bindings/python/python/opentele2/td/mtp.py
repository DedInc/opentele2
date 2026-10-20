"""1.5.0 ``src/td/mtp.py``: only its ``TDataDcIdNotFound``, which
:meth:`~opentele2.td.account.MtpConfigView.endpoints` raises; the MTP config
itself is read by :mod:`opentele2._native`."""

from __future__ import annotations

from .. import _native
from ..exception import OpenTeleException

__all__ = ["TDataDcIdNotFound"]


class TDataDcIdNotFound(OpenTeleException):
    def __init__(self, dcId: int, stack_index: int = 2) -> None:
        super().__init__(_native.dc_not_found_message(int(dcId)), stack_index)
        self.dcId = dcId
