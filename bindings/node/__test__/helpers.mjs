// helpers.mjs: shared fixtures of the opentele2 Node tests.
//
// Key material is compared with assertSame, which never prints the bytes.

import { createHash } from 'node:crypto'
import { readdirSync, readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const require = createRequire(import.meta.url)

/** The native module, loaded the way `require('opentele2')` loads it. */
export const core = require('../index.js')

/** crates/opentele2-core/tests/vectors as a filesystem path. */
export const VECTORS = fileURLToPath(
  new URL('../../../crates/opentele2-core/tests/vectors/', import.meta.url),
)

export const FOLDERS = [
  'tdata_plain/performance_on',
  'tdata_plain/performance_off',
  'tdata_passcode/performance_on',
  'tdata_passcode/performance_off',
]

// The first TCP endpoint of each production DC in 1.5.0, as [IPv4, IPv6].
export const PRODUCTION = {
  1: ['149.154.175.50', '2001:b28:f23d:f001::a'],
  2: ['149.154.167.51', '2001:67c:4e8:f002::a'],
  3: ['149.154.175.100', '2001:b28:f23d:f003::a'],
  4: ['149.154.167.91', '2001:67c:4e8:f004::a'],
  5: ['149.154.171.5', '2001:b28:f23f:f005::a'],
}

export const CLIENTS = [
  'TelegramDesktop',
  'TelegramAndroid',
  'TelegramAndroidX',
  'TelegramIOS',
  'TelegramMacOS',
  'TelegramWeb_A',
  'TelegramWeb_K',
  'Webogram',
]

export const PROFILE_FIELDS = [
  'apiHash',
  'apiId',
  'appVersion',
  'deviceModel',
  'langCode',
  'langPack',
  'systemLangCode',
  'systemVersion',
]

export const MTCUTE_BOOL_FALSE = 0xbc799737

/**
 * The MTP config of crates/opentele2-core/tests/{session,tdata_read}.rs,
 * built through 1.5.0's MTP classes: DC 2 has IPv4 TCP `203.0.113.2:443`
 * first and IPv6 TCP `2001:db8::2` first, DC 1 `198.51.100.1` and
 * `2001:db8::1`, DC 3 only the CDN IPv4 `198.51.100.3`.
 */
export const CUSTOM_CONFIG =
  '000000010000000000000149fffffffe000000080000000200000005000001bb0000000b323030313a6462383a3a32000000000000000200000000000001bb0000000b3230332e302e3131332e32000000000000000200000400000020fb0000000b3230332e302e3131332e33000000100102030405060708090a0b0c0d0e0f100000000200000002000000500000000b3230332e302e3131332e34000000000000000200000011000001bb0000000c323030313a6462383a3a3232000000000000000100000010000001bb0000000c3139382e35312e3130302e31000000000000000100000401000001bb0000000b323030313a6462383a3a3100000020abababababababababababababababababababababababababababababababab0000000300000008000001bb0000000c3139382e35312e3130302e330000000000000001000000cb00000003010203000000030100010000014100002710000000640001d4c00000138800007530000003e8000493e000007530000005dc000000c80002a3000002a3000002a300000000010000001e0000000500000005000000640000001a00680074007400700073003a002f002f0074002e006d0065002f00093a8000004e2000015f90000075300000271000000004000000000000000100000000000004000000000227648000000000000005fffffff90000000800670069006600730000000c00760065006e007500650073'

/**
 * Parses a vector file. Integers that a `number` cannot hold exactly become
 * `bigint`s, read from their source text.
 */
export function loadJson(name) {
  const text = readFileSync(path.join(VECTORS, name), 'utf8')
  return JSON.parse(text, (_key, value, context) => {
    if (typeof value === 'number' && Number.isInteger(value) && !Number.isSafeInteger(value)) {
      if (context === undefined || typeof context.source !== 'string') {
        throw new Error('JSON.parse source text access is required for large integers')
      }
      return BigInt(context.source)
    }
    return value
  })
}

export function unhex(text) {
  return Buffer.from(text, 'hex')
}

/** Fails without showing either value, so key bytes never reach the log. */
export function assertSame(actual, expected, label) {
  if (!(actual instanceof Uint8Array) || !Buffer.from(actual).equals(Buffer.from(expected))) {
    throw new Error(`${label} differs`)
  }
}

/** The relative paths of every file under `root`, `/`-separated and sorted. */
export function listedFiles(root) {
  return readdirSync(root, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => path.relative(root, path.join(entry.parentPath, entry.name)).split(path.sep).join('/'))
    .sort()
}

/** The packed bytes of an IPv4 or IPv6 address text. */
export function packIp(text) {
  if (!text.includes(':')) {
    return Buffer.from(text.split('.').map(Number))
  }
  const [head, tail] = text.split('::')
  const groups = (part) => (part ? part.split(':') : [])
  const left = groups(head)
  const right = tail === undefined ? [] : groups(tail)
  const fill = Array(8 - left.length - right.length).fill('0')
  const out = Buffer.alloc(16)
  ;[...left, ...fill, ...right].forEach((group, n) => out.writeUInt16BE(parseInt(group, 16), n * 2))
  return out
}

/** Telethon's StringSession layout: version '1', then padded base64url. */
export function encodeTelethon(dcId, ip, port, key) {
  const packed = packIp(ip)
  const body = Buffer.alloc(1 + packed.length + 2 + key.length)
  body[0] = dcId
  packed.copy(body, 1)
  body.writeUInt16BE(port, 1 + packed.length)
  Buffer.from(key).copy(body, 3 + packed.length)
  return '1' + body.toString('base64').replaceAll('+', '-').replaceAll('/', '_')
}

export function decodeTelethon(string) {
  if (string[0] !== '1') {
    throw new Error('not a version 1 Telethon session')
  }
  const body = Buffer.from(string.slice(1), 'base64url')
  const ipLength = body.length - 1 - 2 - 256
  return {
    dcId: body[0],
    ip: body.subarray(1, 1 + ipLength),
    port: body.readUInt16BE(1 + ipLength),
    key: body.subarray(3 + ipLength),
  }
}

const sha1 = (...parts) => createHash('sha1').update(Buffer.concat(parts)).digest()

/** tdesktop's `prepareAES_oldmtp`, the reference the IGE tests key from. */
export function prepareAesOldmtp(authKey, msgKey, send = false) {
  const x = send ? 0 : 8
  const a = sha1(msgKey, authKey.subarray(x, x + 32))
  const b = sha1(authKey.subarray(32 + x, 48 + x), msgKey, authKey.subarray(48 + x, 64 + x))
  const c = sha1(authKey.subarray(64 + x, 96 + x), msgKey)
  const d = sha1(msgKey, authKey.subarray(96 + x, 128 + x))
  return {
    key: Buffer.concat([a.subarray(0, 8), b.subarray(8, 20), c.subarray(4, 16)]),
    iv: Buffer.concat([a.subarray(8, 20), b.subarray(0, 8), c.subarray(16, 20), d.subarray(0, 8)]),
  }
}

/** Runs `promise` and returns the error it rejects with. */
export async function rejection(promise) {
  try {
    await promise
  } catch (error) {
    return error
  }
  throw new Error('expected a rejection')
}

/** Calls `fn` and returns the error it throws. */
export function thrown(fn) {
  try {
    fn()
  } catch (error) {
    return error
  }
  throw new Error('expected a throw')
}

/** The plain-object input of a manifest account. */
export function vectorAccount(want) {
  return {
    index: want.index,
    userId: BigInt(want.user_id),
    mainDc: want.main_dc,
    authKey: unhex(want.auth_key),
  }
}
