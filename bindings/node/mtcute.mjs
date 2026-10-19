// mtcute.mjs: the `opentele2/mtcute` entry point.
//
// Helpers that hand opentele2 data to mtcute. Nothing here imports
// @mtcute/core; createCryptoProvider loads @mtcute/node on first call, so
// both stay optional peers.

import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const native = require('./index.js')

/**
 * The mtcute v3 string session of `account`, for `client.importSession()`
 * or the `TelegramClient` constructor's session string.
 */
export function toStringSession(account) {
  return native.mtcuteStringSession(account)
}

/**
 * The `initConnectionOptions` mtcute's `TelegramClient` takes, from an
 * opentele2 `profile()` or `generate()` result. The API id and hash are not
 * part of them; pass `profile.apiId` and `profile.apiHash` to the client.
 */
export function initConnectionOptions(profile) {
  return {
    deviceModel: profile.deviceModel,
    systemVersion: profile.systemVersion,
    appVersion: profile.appVersion,
    systemLangCode: profile.systemLangCode,
    langPack: profile.langPack,
    langCode: profile.langCode,
  }
}

/**
 * mtcute's default Node crypto provider with AES-256-IGE, the per-packet
 * cipher, replaced by the opentele2 core. Every other method, including
 * `initialize`, stays mtcute's own.
 */
export async function createCryptoProvider() {
  let utils
  try {
    utils = await import('@mtcute/node/utils.js')
  } catch (cause) {
    const error = new Error('createCryptoProvider needs the @mtcute/node package', { cause })
    error.code = 'ERR_MODULE_NOT_FOUND'
    throw error
  }
  const provider = new utils.NodeCryptoProvider()
  provider.createAesIge = (key, iv) => ({
    encrypt: (data) => native.aesIgeEncrypt(data, key, iv),
    decrypt: (data) => native.aesIgeDecrypt(data, key, iv),
  })
  return provider
}
