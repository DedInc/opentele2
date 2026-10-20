"""The Telethon, API, exception and class helper names the Telethon
integration works with, in one namespace."""

import asyncio
from collections.abc import Callable
from ctypes import sizeof
from typing import TYPE_CHECKING, Any, TypeVar, Union

import telethon
from telethon import functions, tl, types, utils
from telethon.crypto import AuthKey
from telethon.network.connection.connection import Connection
from telethon.network.connection.tcpfull import ConnectionTcpFull
from telethon.sessions import StringSession
from telethon.sessions.abstract import Session
from telethon.sessions.memory import MemorySession
from telethon.sessions.sqlite import SQLiteSession

from .. import td
from .._compat import (
    APP_VERSION,
    APP_VERSION_STR,
    TDF_MAGIC,
    BaseMetaClass,
    BaseObject,
    PrettyTable,
    format_app_version,
    sharemethod,
)
from ..api import API, APIData, CreateNewSession, LoginFlag, UseCurrentSession
from ..exception import (
    AccountAuthKeyNotFound,
    Expects,
    ExpectStreamStatus,
    LoginFlagInvalid,
    MaxAccountLimit,
    NoInstanceMatched,
    NoPasswordProvided,
    OpenTeleException,
    PasswordIncorrect,
    QDataStreamFailed,
    SessionFileInvalid,
    SessionFileNotFound,
    TDAccountNotLoaded,
    TDataAuthKeyNotFound,
    TDataBadConfigData,
    TDataBadDecryptedDataSize,
    TDataBadDecryptKey,
    TDataBadEncryptedDataSize,
    TDataInvalidCheckSum,
    TDataInvalidMagic,
    TDataReadMapDataFailed,
    TDataReadMapDataIncorrectPasscode,
    TDataSaveFailed,
    TDataWrongPasscode,
    TDesktopHasNoAccount,
    TDesktopNotLoaded,
    TDesktopUnauthorized,
    TelethonUnauthorized,
    TFileNotFound,
)

Dict = dict
List = list
Type = type

__all__ = [
    "API",
    "APP_VERSION",
    "APP_VERSION_STR",
    "TDF_MAGIC",
    "TYPE_CHECKING",
    "APIData",
    "AccountAuthKeyNotFound",
    "Any",
    "AuthKey",
    "BaseMetaClass",
    "BaseObject",
    "Callable",
    "Connection",
    "ConnectionTcpFull",
    "CreateNewSession",
    "Dict",
    "ExpectStreamStatus",
    "Expects",
    "List",
    "LoginFlag",
    "LoginFlagInvalid",
    "MaxAccountLimit",
    "MemorySession",
    "NoInstanceMatched",
    "NoPasswordProvided",
    "OpenTeleException",
    "PasswordIncorrect",
    "PrettyTable",
    "QDataStreamFailed",
    "SQLiteSession",
    "Session",
    "SessionFileInvalid",
    "SessionFileNotFound",
    "StringSession",
    "TDAccountNotLoaded",
    "TDataAuthKeyNotFound",
    "TDataBadConfigData",
    "TDataBadDecryptKey",
    "TDataBadDecryptedDataSize",
    "TDataBadEncryptedDataSize",
    "TDataInvalidCheckSum",
    "TDataInvalidMagic",
    "TDataReadMapDataFailed",
    "TDataReadMapDataIncorrectPasscode",
    "TDataSaveFailed",
    "TDataWrongPasscode",
    "TDesktopHasNoAccount",
    "TDesktopNotLoaded",
    "TDesktopUnauthorized",
    "TFileNotFound",
    "TelethonUnauthorized",
    "Type",
    "TypeVar",
    "Union",
    "UseCurrentSession",
    "asyncio",
    "format_app_version",
    "functions",
    "sharemethod",
    "sizeof",
    "td",
    "telethon",
    "tl",
    "types",
    "utils",
]
