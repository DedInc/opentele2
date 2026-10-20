// tdata-types.d.ts: the shapes `accountMtpConfig` and `accountEndpoints`
// return. Hand-written, since the values are the core's MTP config maps with
// camelCase keys, built at run time rather than from Rust structs; index.d.ts
// references and re-exports them.

/** One DC endpoint (`MTP.DcOptions.Endpoint`). */
export interface Endpoint {
  /** DC id, as stored. */
  id: number
  /** `MTP_FLAG_*` bits. */
  flags: number
  /** IP address text, kept verbatim. */
  ip: string
  /** Port. */
  port: number
  /** Secret; empty for none. */
  secret: Buffer
}

/** The endpoints of one address family, by protocol. */
export interface ProtocolEndpoints {
  /** Every endpoint of the family, in insertion order. */
  tcp: Array<Endpoint>
  /** The endpoints without `MTP_FLAG_TCPO_ONLY` and `MTP_FLAG_SECRET`. */
  http: Array<Endpoint>
}

/**
 * The endpoints of one DC by address family and protocol, as 1.5.0
 * `MTP.Config.endpoints` returns them.
 */
export interface Endpoints {
  /** Endpoints without `MTP_FLAG_IPV6`. */
  ipv4: ProtocolEndpoints
  /** Endpoints with `MTP_FLAG_IPV6`. */
  ipv6: ProtocolEndpoints
  /**
   * The endpoint 1.5.0's session conversions connect to over IPv4: the
   * first IPv4 TCP endpoint; absent without one.
   */
  selectedIpv4?: Endpoint
  /**
   * The endpoint they connect to when IPv6 is asked for: the first IPv6
   * TCP endpoint, else the IPv4 one; absent without either.
   */
  selectedIpv6?: Endpoint
}

/** The endpoints of one DC of a config. */
export interface DcEndpoints {
  /** DC id. */
  dcId: number
  /** Its endpoints, in insertion order. */
  endpoints: Array<Endpoint>
}

/** One CDN RSA public key (`MTP.RSAPublicKey`). */
export interface RsaPublicKey {
  /** DC id of the CDN. */
  dcId: number
  /** Modulus bytes. */
  n: Buffer
  /** Exponent bytes. */
  e: Buffer
}

/** The config fields (`MTP.ConfigFields`), in serialization order. */
export interface MtpConfigFields {
  /** `chatSizeMax`. */
  chatSizeMax: number
  /** `megagroupSizeMax`. */
  megagroupSizeMax: number
  /** `forwardedCountMax`. */
  forwardedCountMax: number
  /** `onlineUpdatePeriod`. */
  onlineUpdatePeriod: number
  /** `offlineBlurTimeout`. */
  offlineBlurTimeout: number
  /** `offlineIdleTimeout`. */
  offlineIdleTimeout: number
  /** `onlineFocusTimeout`. */
  onlineFocusTimeout: number
  /** `onlineCloudTimeout`. */
  onlineCloudTimeout: number
  /** `notifyCloudDelay`. */
  notifyCloudDelay: number
  /** `notifyDefaultDelay`. */
  notifyDefaultDelay: number
  /** `savedGifsLimit`. */
  savedGifsLimit: number
  /** `editTimeLimit`. */
  editTimeLimit: number
  /** `revokeTimeLimit`. */
  revokeTimeLimit: number
  /** `revokePrivateTimeLimit`. */
  revokePrivateTimeLimit: number
  /** `revokePrivateInbox`. */
  revokePrivateInbox: boolean
  /** `stickersRecentLimit`. */
  stickersRecentLimit: number
  /** `stickersFavedLimit`. */
  stickersFavedLimit: number
  /** `pinnedDialogsCountMax`. */
  pinnedDialogsCountMax: number
  /** `pinnedDialogsInFolderMax`. */
  pinnedDialogsInFolderMax: number
  /** `internalLinksDomain`. */
  internalLinksDomain: string
  /** `channelsReadMediaPeriod`. */
  channelsReadMediaPeriod: number
  /** `callReceiveTimeoutMs`. */
  callReceiveTimeoutMs: number
  /** `callRingTimeoutMs`. */
  callRingTimeoutMs: number
  /** `callConnectTimeoutMs`. */
  callConnectTimeoutMs: number
  /** `callPacketTimeoutMs`. */
  callPacketTimeoutMs: number
  /** `webFileDcId`. */
  webFileDcId: number
  /** `txtDomainString`. */
  txtDomainString: string
  /** `phoneCallsEnabled`. */
  phoneCallsEnabled: boolean
  /** `blockedMode`. */
  blockedMode: boolean
  /** `captionLengthMax`. */
  captionLengthMax: number
  /** `reactionDefaultEmoji`. */
  reactionDefaultEmoji: string
  /** `reactionDefaultCustom`. */
  reactionDefaultCustom: bigint
  /** `ratingDecay`. */
  ratingDecay: number
  /** `gifSearchUsername`. */
  gifSearchUsername: string
  /** `venueSearchUsername`. */
  venueSearchUsername: string
}

/** An account's MTP config (`MTP.Config`). */
export interface MtpConfig {
  /** Server environment. */
  environment: 'production' | 'test'
  /** Every DC with its endpoints, in first-seen order. */
  dcs: Array<DcEndpoints>
  /** CDN public keys, in file order. */
  cdnPublicKeys: Array<RsaPublicKey>
  /** Every config field. */
  fields: MtpConfigFields
}
