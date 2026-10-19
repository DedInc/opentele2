// mtcute.d.ts: types of the `opentele2/mtcute` entry point (mtcute.mjs).

import type { ICryptoProvider } from '@mtcute/core/utils.js'

import type { AccountInput, ApiProfile } from './index.js'

/** The `initConnection` fields mtcute's `initConnectionOptions` accepts. */
export interface InitConnectionOptions {
  deviceModel: string
  systemVersion: string
  appVersion: string
  systemLangCode: string
  langPack: string
  langCode: string
}

/**
 * The mtcute v3 string session of `account`, for `client.importSession()`
 * or the `TelegramClient` constructor's session string.
 */
export declare function toStringSession(account: AccountInput): string

/**
 * The `initConnectionOptions` mtcute's `TelegramClient` takes, from an
 * opentele2 `profile()` or `generate()` result; pass `profile.apiId` and
 * `profile.apiHash` to the client separately.
 */
export declare function initConnectionOptions(profile: ApiProfile): InitConnectionOptions

/**
 * mtcute's default Node crypto provider with only `createAesIge` replaced
 * by the opentele2 core. Rejects with code `ERR_MODULE_NOT_FOUND` when
 * `@mtcute/node` is not installed.
 */
export declare function createCryptoProvider(): Promise<ICryptoProvider>
