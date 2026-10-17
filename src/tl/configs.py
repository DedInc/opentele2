import asyncio as asyncio
from collections.abc import Callable as Callable
from ctypes import sizeof as sizeof
from typing import (
    TYPE_CHECKING as TYPE_CHECKING,
)
from typing import (
    Any as Any,
)
from typing import (
    TypeVar as TypeVar,
)
from typing import (
    Union as Union,
)

import telethon as telethon
from telethon import functions as functions
from telethon import tl as tl
from telethon import types as types
from telethon import utils as utils
from telethon.crypto import AuthKey as AuthKey
from telethon.network.connection.connection import Connection as Connection
from telethon.network.connection.tcpfull import ConnectionTcpFull as ConnectionTcpFull
from telethon.sessions import StringSession as StringSession
from telethon.sessions.abstract import Session as Session
from telethon.sessions.memory import MemorySession as MemorySession
from telethon.sessions.sqlite import SQLiteSession as SQLiteSession

from .. import td as td
from ..api import (
    API as API,
)
from ..api import (
    APIData as APIData,
)
from ..api import (
    CreateNewSession as CreateNewSession,
)
from ..api import (
    LoginFlag as LoginFlag,
)
from ..api import (
    UseCurrentSession as UseCurrentSession,
)
from ..exception import *
from ..utils import *

Dict = dict
List = list
Type = type
