from __future__ import annotations

from ..utils import BaseObject
from ..exception import Expects

from typing import Union


__all__ = [
    "BareId",
    "ChatIdType",
    "UserId",
    "ChatId",
    "ChannelId",
    "FakeChatId",
    "PeerId",
    "FileKey",
    "DcId",
    "ShiftedDcId",
    "BuiltInDc",
    "dbi",
    "lskType",
    "BotTrustFlag",
]


class BareId(int):  # nocov
    pass


class ChatIdType(BaseObject):  # nocov
    bare = BareId(0)
    kShift = BareId(0)
    kReservedBit = BareId(0x80)

    def __init__(self, value: BareId) -> None:
        self.bare = value


class UserId(ChatIdType):  # nocov
    kShift = BareId(0)


class ChatId(ChatIdType):  # nocov
    kShift = BareId(1)


class ChannelId(ChatIdType):  # nocov
    kShift = BareId(2)


class FakeChatId(ChatIdType):  # nocov
    kShift = BareId(0x7F)


class PeerId(int):  # nocov
    kChatTypeMask = BareId(0xFFFFFFFFFFFF)
    _RESERVED_BIT_SHIFT = 48
    _LEGACY_PEER_ID_MASK = 0xFFFFFFFF
    _LEGACY_TYPE_MASK = 0xF00000000
    _LEGACY_USER_SHIFT = 0x000000000
    _LEGACY_CHAT_SHIFT = 0x100000000
    _LEGACY_CHANNEL_SHIFT = 0x200000000
    _LEGACY_FAKE_SHIFT = 0xF00000000

    def __init__(self, value) -> None:
        self.value = value

    def Serialize(self):
        Expects(not (self.value & (UserId.kReservedBit << self._RESERVED_BIT_SHIFT)))
        return self.value | (UserId.kReservedBit << self._RESERVED_BIT_SHIFT)

    @staticmethod
    def FromChatIdType(
        id: Union[UserId, ChatId, ChannelId, FakeChatId],
    ) -> PeerId:
        return PeerId(id.bare | (BareId(id.kShift) << PeerId._RESERVED_BIT_SHIFT))

    @staticmethod
    def FromSerialized(serialized: int) -> PeerId:
        flag = UserId.kReservedBit << PeerId._RESERVED_BIT_SHIFT
        legacy = not (serialized & flag)

        if not legacy:
            return PeerId(serialized & (~flag))

        bare = BareId(serialized & PeerId._LEGACY_PEER_ID_MASK)
        peer_type = serialized & PeerId._LEGACY_TYPE_MASK

        if peer_type == PeerId._LEGACY_USER_SHIFT:
            return PeerId.FromChatIdType(UserId(bare))
        elif peer_type == PeerId._LEGACY_CHAT_SHIFT:
            return PeerId.FromChatIdType(ChatId(bare))
        elif peer_type == PeerId._LEGACY_CHANNEL_SHIFT:
            return PeerId.FromChatIdType(ChannelId(bare))
        elif peer_type == PeerId._LEGACY_FAKE_SHIFT:
            return PeerId.FromChatIdType(FakeChatId(bare))

        return PeerId(0)


class FileKey(int):  # nocov
    pass


class DcId(int):  # nocov
    kDcShift: DcId = 10000  # type: ignore
    Invalid: DcId = 0  # type: ignore
    _0: DcId = 0  # type: ignore
    _1: DcId = 1  # type: ignore
    _2: DcId = 2  # type: ignore
    _3: DcId = 3  # type: ignore
    _4: DcId = 4  # type: ignore
    _5: DcId = 5  # type: ignore

    @staticmethod
    def BareDcId(shiftedDcId: Union[ShiftedDcId, DcId]) -> DcId:
        return DcId(shiftedDcId % DcId.kDcShift)


class ShiftedDcId(DcId):  # nocov
    @staticmethod
    def ShiftDcId(dcId: DcId, value: int) -> ShiftedDcId:
        return ShiftedDcId(dcId + DcId.kDcShift * value)


class BuiltInDc(BaseObject):  # type: ignore # nocov
    def __init__(self, id: DcId, ip: str, port: int):
        self.id = id
        self.ip = ip
        self.port = port


BuiltInDc.kBuiltInDcs = [  # nocov
    BuiltInDc(DcId._1, "149.154.175.50", 443),
    BuiltInDc(DcId._2, "149.154.167.51", 443),
    BuiltInDc(DcId._2, "95.161.76.100", 443),
    BuiltInDc(DcId._3, "149.154.175.100", 443),
    BuiltInDc(DcId._4, "149.154.167.91", 443),
    BuiltInDc(DcId._5, "149.154.171.5", 443),
]

BuiltInDc.kBuiltInDcsIPv6 = [  # nocov
    BuiltInDc(DcId._1, "2001:0b28:f23d:f001:0000:0000:0000:000a", 443),
    BuiltInDc(DcId._2, "2001:067c:04e8:f002:0000:0000:0000:000a", 443),
    BuiltInDc(DcId._3, "2001:0b28:f23d:f003:0000:0000:0000:000a", 443),
    BuiltInDc(DcId._4, "2001:067c:04e8:f004:0000:0000:0000:000a", 443),
    BuiltInDc(DcId._5, "2001:0b28:f23f:f005:0000:0000:0000:000a", 443),
]

BuiltInDc.kBuiltInDcsTest = [  # nocov
    BuiltInDc(DcId._1, "149.154.175.10", 443),
    BuiltInDc(DcId._2, "149.154.167.40", 443),
    BuiltInDc(DcId._3, "149.154.175.117", 443),
]

BuiltInDc.kBuiltInDcsIPv6Test = [  # nocov
    BuiltInDc(DcId._1, "2001:0b28:f23d:f001:0000:0000:0000:000e", 443),
    BuiltInDc(DcId._2, "2001:067c:04e8:f002:0000:0000:0000:000e", 443),
    BuiltInDc(DcId._3, "2001:0b28:f23d:f003:0000:0000:0000:000e", 443),
]


class dbi(int):  # nocov
    Key = 0x00
    User = 0x01
    DcOptionOldOld = 0x02
    ChatSizeMaxOld = 0x03
    MutePeerOld = 0x04
    SendKeyOld = 0x05
    AutoStart = 0x06
    StartMinimized = 0x07
    SoundFlashBounceNotifyOld = 0x08
    WorkModeOld = 0x09
    SeenTrayTooltip = 0x0A
    DesktopNotifyOld = 0x0B
    AutoUpdate = 0x0C
    LastUpdateCheck = 0x0D
    WindowPositionOld = 0x0E
    ConnectionTypeOldOld = 0x0F
    # 0x10 reserved
    DefaultAttach = 0x11
    CatsAndDogsOld = 0x12
    ReplaceEmojiOld = 0x13
    AskDownloadPathOld = 0x14
    DownloadPathOldOld = 0x15
    ScaleOld = 0x16
    EmojiTabOld = 0x17
    RecentEmojiOldOldOld = 0x18
    LoggedPhoneNumberOld = 0x19
    MutedPeersOld = 0x1A
    # 0x1b reserved
    NotifyViewOld = 0x1C
    SendToMenu = 0x1D
    CompressPastedImageOld = 0x1E
    LangOld = 0x1F
    LangFileOld = 0x20
    TileBackgroundOld = 0x21
    AutoLockOld = 0x22
    DialogLastPath = 0x23
    RecentEmojiOldOld = 0x24
    EmojiVariantsOldOld = 0x25
    RecentStickers = 0x26
    DcOptionOld = 0x27
    TryIPv6Old = 0x28
    SongVolumeOld = 0x29
    WindowsNotificationsOld = 0x30
    IncludeMutedOld = 0x31
    MegagroupSizeMaxOld = 0x32
    DownloadPathOld = 0x33
    AutoDownloadOld = 0x34
    SavedGifsLimitOld = 0x35
    ShowingSavedGifsOld = 0x36
    AutoPlayOld = 0x37
    AdaptiveForWideOld = 0x38
    HiddenPinnedMessagesOld = 0x39
    RecentEmojiOld = 0x3A
    EmojiVariantsOld = 0x3B
    DialogsModeOld = 0x40
    ModerateModeOld = 0x41
    VideoVolumeOld = 0x42
    StickersRecentLimitOld = 0x43
    NativeNotificationsOld = 0x44
    NotificationsCountOld = 0x45
    NotificationsCornerOld = 0x46
    ThemeKeyOld = 0x47
    DialogsWidthRatioOld = 0x48
    UseExternalVideoPlayer = 0x49
    DcOptionsOld = 0x4A
    MtpAuthorization = 0x4B
    LastSeenWarningSeenOld = 0x4C
    SessionSettings = 0x4D
    LangPackKey = 0x4E
    ConnectionTypeOld = 0x4F
    StickersFavedLimitOld = 0x50
    SuggestStickersByEmojiOld = 0x51
    SuggestEmojiOld = 0x52
    TxtDomainStringOldOld = 0x53
    ThemeKey = 0x54
    TileBackground = 0x55
    CacheSettingsOld = 0x56
    AnimationsDisabled = 0x57
    ScalePercent = 0x58
    PlaybackSpeedOld = 0x59
    LanguagesKey = 0x5A
    CallSettingsOld = 0x5B
    CacheSettings = 0x5C
    TxtDomainStringOld = 0x5D
    ApplicationSettings = 0x5E
    DialogsFiltersOld = 0x5F
    FallbackProductionConfig = 0x60
    BackgroundKey = 0x61

    EncryptedWithSalt = 333
    Encrypted = 444

    Version = 666


class lskType(int):  # nocov
    lskUserMap = 0x00
    lskDraft = 0x01  # data: PeerId peer
    lskDraftPosition = 0x02  # data: PeerId peer
    lskLegacyImages = 0x03  # legacy
    lskLocations = 0x04
    lskLegacyStickerImages = 0x05  # legacy
    lskLegacyAudios = 0x06  # legacy
    lskRecentStickersOld = 0x07
    lskBackgroundOldOld = 0x08
    lskUserSettings = 0x09
    lskRecentHashtagsAndBots = 0x0A
    lskStickersOld = 0x0B
    lskSavedPeersOld = 0x0C
    lskReportSpamStatusesOld = 0x0D
    lskSavedGifsOld = 0x0E
    lskSavedGifs = 0x0F
    lskStickersKeys = 0x10
    lskTrustedBots = 0x11
    lskFavedStickers = 0x12
    lskExportSettings = 0x13
    lskBackgroundOld = 0x14
    lskSelfSerialized = 0x15  # serialized self
    lskMasksKeys = 0x16
    lskCustomEmojiKeys = 0x17
    lskSearchSuggestions = 0x18
    lskWebviewTokens = 0x19  # data: QByteArray bots, QByteArray other


class BotTrustFlag(int):  # nocov
    NoOpenGame = 1 << 0
    Payment = 1 << 1
