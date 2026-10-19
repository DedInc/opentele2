// types.ts: compile-only usage of index.d.ts, mtcute.d.ts and telethon.d.ts
// through the package's own `exports`, checked by `pnpm run typecheck`.
// It is never run; the synthetic key is zeros.
//
// tsconfig.json sets skipLibCheck, since @mtcute/core's declarations name
// Deno and DOM types that no Node setup provides; the `@ts-expect-error`
// lines fail the check if a declaration here degrades to `any`.

import { profile, sessionPairPaths, telethonSessionRows } from 'opentele2'
import type { AccountInput, ApiProfile, SessionPairPaths, TelethonSessionRows } from 'opentele2'
import { initConnectionOptions, toStringSession } from 'opentele2/mtcute'
import type { InitConnectionOptions } from 'opentele2/mtcute'
import { loadSessionPair, readSessionFile, saveSessionPair, writeSessionFile } from 'opentele2/telethon'
import type { LoadedSessionPair, ReadSessionRows, WriteSessionRows } from 'opentele2/telethon'

export async function usage(): Promise<void> {
  const account: AccountInput = { index: 0, userId: 77n, mainDc: 2, authKey: new Uint8Array(256) }
  const desktop: ApiProfile = profile('TelegramDesktop')
  const options: InitConnectionOptions = initConnectionOptions(desktop)
  const session: string = toStringSession(account)

  const native: TelethonSessionRows = telethonSessionRows(account, true)
  const written: string = await writeSessionFile('acc', native)
  const wide: WriteSessionRows = { ...native, takeoutId: -(2n ** 63n) }
  await writeSessionFile(written, wide)
  const read: ReadSessionRows = await readSessionFile(written)
  const takeout: number | bigint | undefined = read.takeoutId

  const paths: SessionPairPaths = await saveSessionPair('acc', account, desktop, {
    ipv6: false,
    extra: { phone: '15550100' },
  })
  const same: SessionPairPaths = sessionPairPaths(paths.json)
  const loaded: LoadedSessionPair = await loadSessionPair(same.session)
  const apiId: number = loaded.profile.apiId
  const key: Uint8Array = loaded.rows.authKey

  void [options, session, takeout, apiId, key]
}

export async function misuse(account: AccountInput, desktop: ApiProfile, rows: ReadSessionRows): Promise<void> {
  // @ts-expect-error the path is a string
  await writeSessionFile(1, rows)
  // @ts-expect-error a takeout id is a number or bigint
  const text: string = rows.takeoutId
  // @ts-expect-error the DC id is a number
  const dc: string = rows.dcId
  // @ts-expect-error ipv6 is a boolean
  await saveSessionPair('acc', account, desktop, { ipv6: 'yes' })
  // @ts-expect-error the pair paths are strings
  const json: number = (await loadSessionPair('acc')).paths.json
  // @ts-expect-error the companion's profile is an ApiProfile
  const device: number = (await loadSessionPair('acc')).profile.deviceModel
  // @ts-expect-error the mtcute options carry no API id
  void initConnectionOptions(desktop).apiId
  void [text, dc, json, device]
}
