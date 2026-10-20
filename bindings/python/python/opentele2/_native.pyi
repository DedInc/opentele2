# Type stub of the opentele2._native extension module (bindings/python/src).
# Docstrings live in the extension; this file carries the types only.

import os
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Literal, Protocol, TypedDict, final, overload

from typing_extensions import NotRequired, TypeAlias

__version__: str

_Bytes: TypeAlias = bytes | bytearray
_Passcode: TypeAlias = bytes | bytearray | str
_Path: TypeAlias = str | os.PathLike[str]
_LoadRequest: TypeAlias = (
    _Path | tuple[_Path] | tuple[_Path, _Passcode] | tuple[_Path, _Passcode, str | None]
)
_Client: TypeAlias = Literal[
    "TelegramDesktop",
    "TelegramAndroid",
    "TelegramAndroidX",
    "TelegramIOS",
    "TelegramMacOS",
    "TelegramWeb_A",
    "TelegramWeb_K",
    "Webogram",
]
_DesktopSystem: TypeAlias = Literal["windows", "macos", "linux"]
StrictMode: TypeAlias = Literal["off", "warn", "strict"]
_IssueKind: TypeAlias = Literal[
    "UnknownLangPack",
    "ShortLangCode",
    "MissingRegion",
    "EmptyDeviceModel",
    "EmptySystemVersion",
    "EmptyAppVersion",
    "ApiIdMismatch",
    "AppVersionMajor",
    "AndroidSdkRange",
]
_Severity: TypeAlias = Literal["note", "warning", "error"]

class CoreError(Exception):
    # Stable SCREAMING_SNAKE identifier, for example "TDATA_WRONG_PASSCODE"
    # or "SRP_BAD_B".
    code: str
    # Human-readable text; may change between releases.
    message: str
    # The message 1.5.0 gave the matching exception; `message` when none
    # was given.
    legacy_message: str
    # Stable SCREAMING_SNAKE code of a context raised differently from the
    # rest of `code`, such as "BAD_ACCOUNTS_COUNT"; None for most errors.
    detail_code: str | None
    def __init__(self, code: str, message: str, legacy_message: str | None = None) -> None: ...

# The values a client sends in initConnection.
class ApiProfile(TypedDict):
    api_id: int
    api_hash: str
    device_model: str
    system_version: str
    app_version: str
    lang_code: str
    system_lang_code: str
    lang_pack: str

# Overrides of the offline PlatformVersions fields.
class Versions(TypedDict, total=False):
    android_app_version: str
    android_app_version_code: int
    android_sdk_range: tuple[int, int]
    android_latest_sdk: int
    ios_app_version: str
    ios_build_number: int
    ios_version_range: tuple[str, str]
    ios_system_version: str
    macos_system_version: str
    desktop_app_version: str
    desktop_app_version_suffix: str
    macos_app_version: str
    macos_build_number: int
    android_x_app_version: str
    web_a_version: str
    web_k_version: str
    chrome_version: str
    user_agent: str

# Every field of 1.5.0 PlatformVersions; also a valid override set.
class PlatformVersions(TypedDict):
    android_app_version: str
    android_app_version_code: int
    android_sdk_range: tuple[int, int]
    android_latest_sdk: int
    ios_app_version: str
    ios_build_number: int
    ios_version_range: tuple[str, str]
    ios_system_version: str
    macos_system_version: str
    desktop_app_version: str
    desktop_app_version_suffix: str
    macos_app_version: str
    macos_build_number: int
    android_x_app_version: str
    web_a_version: str
    web_k_version: str
    chrome_version: str
    user_agent: str

_VersionsArg: TypeAlias = Versions | PlatformVersions

# The fields the release feeds answered, never empty; a field no source
# answered is absent.
class VersionsPatch(TypedDict, total=False):
    desktop_app_version: str | None
    android_app_version: str | None
    android_app_version_code: int | None
    android_x_app_version: str | None
    ios_app_version: str | None
    ios_build_number: int | None
    macos_app_version: str | None
    macos_build_number: int | None
    web_k_version: str | None
    web_a_version: str | None
    chrome_version: str | None
    firefox_version: str | None

# The TL schema layer opentele2 advertises.
LAYER: int

# crypto: failures raise CoreError, bad lengths with code "BAD_LENGTH".

def key_id(auth_key: _Bytes) -> int: ...
def prepare_aes_oldmtp(
    auth_key: _Bytes, msg_key: _Bytes, send: bool = False
) -> tuple[bytes, bytes]: ...
def aes_ige_encrypt(data: _Bytes, key: _Bytes, iv: _Bytes) -> bytes: ...
def aes_ige_decrypt(data: _Bytes, key: _Bytes, iv: _Bytes) -> bytes: ...
def encrypt_local(data: _Bytes, local_key: _Bytes) -> bytes: ...
def decrypt_local(encrypted: _Bytes, local_key: _Bytes) -> bytes: ...
def create_local_key(passcode: _Passcode, salt: _Bytes) -> bytes: ...
def create_legacy_local_key(passcode: _Passcode, salt: _Bytes) -> bytes: ...
def argon2id(
    passcode: _Passcode, salt: _Bytes, memory_kib: int, time: int, lanes: int
) -> bytes: ...
def sha1(data: _Bytes) -> bytes: ...
def sha256(data: _Bytes) -> bytes: ...
def hmac_sha256(key: _Bytes, data: _Bytes) -> bytes: ...

# Zero iterations or a digest other than sha1/sha256/sha512 raise CoreError
# "INVALID_INPUT".
def pbkdf2(
    password: _Passcode,
    salt: _Bytes,
    iterations: int,
    key_len: int = 64,
    digest: str = "sha512",
) -> bytes: ...

# pq is 1 to 8 big-endian bytes; p <= q as minimal big-endian bytes.
def factorize_pq(pq: _Bytes) -> tuple[bytes, bytes]: ...
def random_bytes(size: int) -> bytes: ...
def gzip(data: _Bytes, max_size: int | None = None) -> bytes | None: ...
def gunzip(data: _Bytes) -> bytes: ...

@final
class AesCtr:
    def __new__(cls, key: _Bytes, iv: _Bytes) -> AesCtr: ...
    def process(self, data: _Bytes) -> bytes: ...

# cryptg 0.6.0 interface, raising ValueError on bad lengths; the submodule is
# also importable as opentele2._native.cryptg, and `import opentele2` registers
# it as the top-level cryptg when no real cryptg is installed.
class _Cryptg(Protocol):
    def encrypt_ige(self, data: _Bytes, key: _Bytes, iv: _Bytes) -> bytes: ...
    def decrypt_ige(self, data: _Bytes, key: _Bytes, iv: _Bytes) -> bytes: ...

cryptg: _Cryptg

# tdata: repr() of Account and TData never shows key bytes.

# The 1.5.0 messages of TDataSaveFailed and MaxAccountLimit.
SAVE_FAILED_MESSAGE: str
MAX_ACCOUNT_LIMIT_MESSAGE: str

@final
class Account:
    def __new__(
        cls,
        index: int,
        user_id: int,
        main_dc: int,
        keys: Iterable[tuple[int, _Bytes]],
        config: _Bytes | None = None,
    ) -> Account: ...
    @property
    def index(self) -> int: ...
    @property
    def user_id(self) -> int: ...
    @property
    def main_dc(self) -> int: ...
    @property
    def auth_key(self) -> bytes: ...
    @property
    def keys(self) -> list[tuple[int, bytes]]: ...
    @property
    def config(self) -> bytes | None: ...

@final
class TData:
    MAX_ACCOUNTS: int
    @staticmethod
    def load(path: _Path, passcode: _Passcode = b"", key_file: str | None = None) -> TData: ...
    @staticmethod
    def new(
        accounts: Sequence[Account],
        passcode: _Passcode = b"",
        performance_mode: bool = True,
        active_index: int = -1,
        draws: Iterable[_Bytes] | None = None,
    ) -> TData: ...
    def save(
        self,
        path: _Path,
        performance_mode: bool | None = None,
        draws: Iterable[_Bytes] | None = None,
    ) -> None: ...
    def migrate(self, draws: Iterable[_Bytes] | None = None) -> bool: ...
    def add_account(self, user_id: int, main_dc: int, auth_key: _Bytes) -> int: ...
    @property
    def accounts(self) -> list[Account]: ...
    @accounts.setter
    def accounts(self, value: Sequence[Account]) -> None: ...
    @property
    def active_index(self) -> int: ...
    @active_index.setter
    def active_index(self, value: int) -> None: ...
    @property
    def performance_mode(self) -> bool: ...
    @performance_mode.setter
    def performance_mode(self, value: bool) -> None: ...
    @property
    def app_version(self) -> int: ...
    @property
    def local_key(self) -> bytes: ...
    @property
    def passcode_key(self) -> bytes: ...
    @property
    def main_account(self) -> Account | None: ...
    @property
    def key_file(self) -> str: ...
    @key_file.setter
    def key_file(self, value: str) -> None: ...
    @property
    def legacy_key_file(self) -> bool: ...

def load_many(
    requests: Iterable[_LoadRequest], threads: int | None = None
) -> list[TData | CoreError]: ...

TDF_MAGIC: bytes

class DrawPlanParams(TypedDict, total=False):
    has_passcode: bool
    performance_mode: bool

@overload
def draw_plan(operation: Literal["new"], target: DrawPlanParams) -> list[int]: ...
@overload
def draw_plan(operation: Literal["migrate", "save"], target: TData) -> list[int]: ...

# MTP configs: endpoint flags, as tdesktop stores them.

MTP_FLAG_IPV6: int
MTP_FLAG_MEDIA_ONLY: int
MTP_FLAG_TCPO_ONLY: int
MTP_FLAG_CDN: int
MTP_FLAG_STATIC: int
MTP_FLAG_THIS_PORT_ONLY: int
MTP_FLAG_SECRET: int

class Endpoint(TypedDict):
    id: int
    flags: int
    ip: str
    port: int
    secret: bytes

class ProtocolEndpoints(TypedDict):
    tcp: list[Endpoint]
    http: list[Endpoint]

class Endpoints(TypedDict):
    ipv4: ProtocolEndpoints
    ipv6: ProtocolEndpoints
    selected_ipv4: Endpoint | None
    selected_ipv6: Endpoint | None

class DcEndpoints(TypedDict):
    dc_id: int
    endpoints: list[Endpoint]

class RsaPublicKey(TypedDict):
    dc_id: int
    n: bytes
    e: bytes

class MtpConfigFields(TypedDict):
    chat_size_max: int
    megagroup_size_max: int
    forwarded_count_max: int
    online_update_period: int
    offline_blur_timeout: int
    offline_idle_timeout: int
    online_focus_timeout: int
    online_cloud_timeout: int
    notify_cloud_delay: int
    notify_default_delay: int
    saved_gifs_limit: int
    edit_time_limit: int
    revoke_time_limit: int
    revoke_private_time_limit: int
    revoke_private_inbox: bool
    stickers_recent_limit: int
    stickers_faved_limit: int
    pinned_dialogs_count_max: int
    pinned_dialogs_in_folder_max: int
    internal_links_domain: str
    channels_read_media_period: int
    call_receive_timeout_ms: int
    call_ring_timeout_ms: int
    call_connect_timeout_ms: int
    call_packet_timeout_ms: int
    web_file_dc_id: int
    txt_domain_string: str
    phone_calls_enabled: bool
    blocked_mode: bool
    caption_length_max: int
    reaction_default_emoji: str
    reaction_default_custom: int
    rating_decay: int
    gif_search_username: str
    venue_search_username: str

class MtpConfig(TypedDict):
    environment: Literal["production", "test"]
    dcs: list[DcEndpoints]
    cdn_public_keys: list[RsaPublicKey]
    fields: MtpConfigFields

def account_mtp_config(account: Account | None = None) -> MtpConfig: ...
def account_endpoints(
    account: Account | None = None, dc_id: int | None = None
) -> Endpoints | None: ...

# sessions

def telethon_string_session(account: Account, ipv6: bool = False) -> str: ...
def mtcute_string_session(account: Account) -> str: ...

# Telethon .session files (version 8) and their .json companion.

TELETHON_SESSION_VERSION: int
TELETHON_SESSION_SUFFIX: str
TELETHON_JSON_SUFFIX: str
TELETHON_DELETE_VERSION: str
TELETHON_INSERT_VERSION: str
TELETHON_DELETE_SESSIONS: str
TELETHON_INSERT_SESSION: str

class TelethonTable(TypedDict):
    name: str
    ddl: str
    columns: list[str]

class TelethonSessionRows(TypedDict):
    dc_id: int
    server_address: str
    port: int
    auth_key: bytes
    takeout_id: int | None

def telethon_schema() -> list[TelethonTable]: ...
def telethon_session_rows(account: Account, ipv6: bool = False) -> TelethonSessionRows: ...
def session_pair_paths(base: _Path) -> tuple[str, str]: ...
def session_path(path: _Path) -> str: ...
def session_companion_json(
    profile: ApiProfile, extra: dict[str, Any] | None = None
) -> dict[str, Any]: ...

# json.dumps(obj, indent=2, ensure_ascii=False); TypeError for a value
# JSON cannot hold.
def py_json_text(obj: object) -> str: ...

# Raises CoreError INVALID_INPUT, legacy_message 1.5.0's SessionFileInvalid
# text; the profile is None when its keys are not the strict typed form.
def read_session_companion(text: str) -> tuple[ApiProfile | None, dict[str, Any]]: ...
def write_session_file(
    path: _Path,
    dc_id: int,
    server_address: str,
    port: int,
    auth_key: _Bytes,
    takeout_id: int | None = None,
) -> str: ...
def read_session_file(path: _Path) -> TelethonSessionRows: ...

# fingerprints

def platform_versions(overrides: _VersionsArg | None = None) -> PlatformVersions: ...
def profile(client: _Client, versions: _VersionsArg | None = None) -> ApiProfile: ...
def generate(
    client: _Client,
    seed: str | int | None = None,
    system: _DesktopSystem | None = None,
    versions: _VersionsArg | None = None,
) -> ApiProfile: ...
def profile_from_session_json(json: str | dict[str, Any]) -> ApiProfile: ...
def profile_to_session_json(
    profile: ApiProfile, extra: dict[str, Any] | None = None
) -> dict[str, Any]: ...
def profiles_equal(a: ApiProfile, b: ApiProfile) -> bool: ...
def format_app_version(version: int) -> str: ...

# (key, attribute, default, fallback) of each session JSON profile key, in
# the order APIData.to_json writes them.
SESSION_JSON_FIELDS: list[tuple[str, str, str | None, str | None]]
# 1.5.0 _DEFAULT_EXTRA_FIELDS as (key, default) items, in order.
DEFAULT_EXTRA_FIELDS: list[tuple[str, str | bool | None]]

# device catalogs

_Platform: TypeAlias = Literal["windows", "linux", "macos", "android", "ios", "web_a", "web_k"]

class CatalogEntry(TypedDict):
    model: str
    system_version: str
    weight: int

def catalog_entries(platform: _Platform) -> list[CatalogEntry]: ...
def device_models(platform: _Platform) -> list[str]: ...
def system_versions(platform: _Platform) -> list[str]: ...

WEB_BROWSER_WEIGHTS: dict[str, int]

# The per-request timeout fetch_versions defaults to, in seconds.
DEFAULT_TIMEOUT: float

# Current versions from the release feeds, keyed by VersionsPatch field;
# never raises for the network.
def fetch_versions(timeout: float = ...) -> dict[str, str | int]: ...

# A patch: VersionsPatch fields, None for an absent one.
def apply_versions_patch(
    versions: _VersionsArg | None, patch: VersionsPatch | Mapping[str, str | int | None]
) -> PlatformVersions: ...

# initConnection fingerprint checks.

STRICT_MODES: tuple[StrictMode, ...]

class Issue(TypedDict):
    kind: _IssueKind
    severity: _Severity
    message: str

class FingerprintConfig(TypedDict):
    strict_mode: StrictMode
    auto_validate: bool
    preferred_transport: str
    warn_on_layer_mismatch: bool
    layer_override: int | None
    randomize_msg_id_offset: bool
    msg_id_offset: int

def tz_offset(offset_seconds: int) -> float: ...
def validate_init_params(
    profile: ApiProfile, versions: _VersionsArg | None = None, mode: StrictMode = "warn"
) -> list[Issue]: ...

# The seven validate_init_connection_params arguments by name, as given:
# api_id of any type, the texts str or None, lang_pack any value. A missing
# or unknown key raises TypeError.
_RawInitParams: TypeAlias = dict[str, Any]

def validate_raw_init_params(
    params: _RawInitParams, versions: _VersionsArg | None = None, mode: StrictMode = "warn"
) -> list[Issue]: ...
def check_versions(profile: ApiProfile, versions: _VersionsArg | None = None) -> list[Issue]: ...
def issues_message(issues: Iterable[Issue]) -> str: ...

MSG_ID_OFFSET_MAX: int

def msg_id_offset() -> int: ...
def is_valid_msg_id(msg_id: int, from_client: bool, now_unix: float) -> bool: ...
def fingerprint_config(
    *,
    strict_mode: StrictMode | None = None,
    auto_validate: bool | None = None,
    preferred_transport: str | None = None,
    warn_on_layer_mismatch: bool | None = None,
    layer_override: int | None = None,
    randomize_msg_id_offset: bool | None = None,
    msg_id_offset: int | None = None,
) -> FingerprintConfig: ...
def validate_fingerprint(
    config: FingerprintConfig, profile: ApiProfile, versions: _VersionsArg | None = None
) -> list[Issue]: ...
def validate_raw_fingerprint(
    strict_mode: StrictMode,
    auto_validate: bool,
    params: _RawInitParams,
    versions: _VersionsArg | None = None,
) -> list[Issue]: ...
def effective_layer(config: FingerprintConfig) -> int: ...
def effective_layer_for(
    library_layer: int, layer_override: int | None = None
) -> tuple[int, str | None]: ...
def layer_mismatch_warning(library_layer: int) -> str | None: ...

# Login, session admin and consistency checks.

QR_LOGIN_URL_PREFIX: str
SRP_NUMBER_SIZE: int
NO_PASSWORD_PROVIDED: str
FRESH_RESET_FORBIDDEN: str
HASH_INVALID: str
SESSIONS_UNAVAILABLE: str
OFFICIAL_API_IDS: tuple[int, ...]
SESSION_COLUMNS: tuple[str, ...]
LAYER_TOLERANCE: int
CURRENT_SESSION_MISSING: str
LANG_PACK_EMPTY: str
NO_APP_UPDATE: str
TERMS_OF_SERVICE_OK: str
CONSISTENCY_WARNING_PREFIX: str
SRP_ALGORITHM: str
QR_LOGIN_ATTEMPTS: int
QR_EXPIRE_SAFETY_SECONDS: int
QR_LOGIN_TIMEOUT: str
QR_TIMEOUT_ERROR_TYPE: str
EXISTING_SESSION_KEPT: str
EXISTING_SESSION_REPLACED: str
POST_LOGIN_APP_UPDATE_SOURCE: str
POST_LOGIN_COUNTRIES_LANG_CODE: str

# One step of the 1.5.0 post-login sequence: the request's TL name, such as
# "help.getConfig", and the inclusive range of the sleep before it.
class PostLoginStep(TypedDict):
    request: str
    delay_ms: tuple[int, int] | None

POST_LOGIN_STEPS: tuple[PostLoginStep, ...]

# The account.Password fields srp_check needs.
class SrpParams(TypedDict):
    srp_id: int
    g: int
    p: _Bytes
    salt1: _Bytes
    salt2: _Bytes
    srp_b: _Bytes

# The values of an inputCheckPasswordSRP.
class SrpCheck(TypedDict):
    srp_id: int
    a: bytes
    m1: bytes

class SessionRow(TypedDict):
    current: NotRequired[bool]
    device_model: str
    platform: str
    system_version: str
    api_id: int
    app_name: str
    app_version: str
    official_app: NotRequired[bool]

class ConsistencyExpectations(TypedDict):
    api_id: int
    official_api_id: bool
    lang_pack: str
    lang_pack_skipped: bool
    advertised_layer: int
    layer_tolerance: int
    app_version: str
    version_issues: list[Issue]
    app_version_current: bool

class CheckResult(TypedDict):
    name: str
    passed: bool
    detail: str

# How one check ended: it returned a result...
class CheckFinished(TypedDict):
    passed: bool
    detail: str

# ...or raised out of its own handling with this str(e).
class CheckRaised(TypedDict):
    raised: str

CheckOutcome: TypeAlias = CheckFinished | CheckRaised

class ConsistencyReport(TypedDict):
    checks: list[CheckResult]
    all_passed: bool
    summary: str
    warning: str | None

# The attributes session_row reads; Telethon's types.Authorization has them.
class _Authorization(Protocol):
    @property
    def current(self) -> bool | None: ...
    @property
    def device_model(self) -> str: ...
    @property
    def platform(self) -> str: ...
    @property
    def system_version(self) -> str: ...
    @property
    def api_id(self) -> int: ...
    @property
    def app_name(self) -> str: ...
    @property
    def app_version(self) -> str: ...
    @property
    def official_app(self) -> bool | None: ...

def qr_login_url(token: _Bytes) -> str: ...
def unsupported_password_algorithm(algorithm: str) -> str: ...
def qr_attempt_timeout_warning(attempt_number: int, error_type: str | None = None) -> str: ...
def qr_attempt_retry_warning(attempt_number: int) -> str: ...
def post_login_steps(lang_pack: str) -> list[PostLoginStep]: ...

# Raises ValueError when min_ms > max_ms, as random.randint does.
def random_delay_ms(min_ms: int, max_ms: int) -> int: ...
def session_row(authorization: _Authorization) -> SessionRow: ...

# Raises ValueError unless there is one outcome per consistency_checks() name.
def consistency_report(outcomes: Iterable[CheckOutcome]) -> ConsistencyReport: ...

# Raises CoreError "SRP_BAD_PRIME_OR_GENERATOR", "SRP_BAD_B" or
# "SRP_NO_GOOD_RANDOM", and ValueError when `exponents` runs out.
def srp_check(
    params: SrpParams, password: str, exponents: Iterable[_Bytes] | None = None
) -> SrpCheck: ...
def is_official_api_id(api_id: int) -> bool: ...
def format_sessions(rows: Iterable[SessionRow]) -> str: ...
def format_table(
    headers: Sequence[str], rows: Sequence[Sequence[str]], add_split: Sequence[int] | None = None
) -> str: ...
def consistency_expectations(
    profile: ApiProfile, versions: _VersionsArg | None = None
) -> ConsistencyExpectations: ...
def consistency_checks() -> list[str]: ...
def layer_result(library_layer: int, advertised_layer: int | None = None) -> CheckResult: ...
def consistency_summary(results: Iterable[CheckResult]) -> str: ...
def get_config_detail(this_dc: int | None = None) -> str: ...
def get_config_error(error: str) -> str: ...
def nearest_dc_detail(country: str, this_dc: int, nearest_dc: int) -> str: ...
def nearest_dc_error(error: str) -> str: ...
def current_session_detail(row: SessionRow) -> str: ...
def layer_detail(library_layer: int, advertised_layer: int | None = None) -> str: ...
def lang_pack_detail(lang_pack: str, languages: int) -> str: ...
def lang_pack_error(lang_pack: str, error: str) -> str: ...
def app_update_detail(version: str | None = None) -> str: ...
def app_update_error(error: str) -> str: ...
def check_error(error: str) -> str: ...
def check_exception(error: str) -> str: ...
