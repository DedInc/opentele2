// types.ts: compile-only usage of index.d.ts, mtcute.d.ts and telethon.d.ts
// through the package's own `exports`, checked by `pnpm run typecheck`.
// It is never run; the synthetic key is zeros.
//
// tsconfig.json sets skipLibCheck, since @mtcute/core's declarations name
// Deno and DOM types that no Node setup provides; the `@ts-expect-error`
// lines fail the check if a declaration here degrades to `any`.

import {
  TDATA_MAX_ACCOUNTS,
  TDF_MAGIC,
  addTdataAccount,
  catalogEntries,
  defaultExtraFields,
  deviceModels,
  drawPlan,
  formatAppVersion,
  formatTable,
  loadTdata,
  migrateTdata,
  newTdata,
  profile,
  saveTdata,
  sessionJsonFields,
  sessionPairPaths,
  telethonSessionRows,
  webBrowserWeights,
} from 'opentele2'
import type {
  AccountInput,
  ApiProfile,
  CatalogEntry,
  SessionJsonField,
  SessionPairPaths,
  TData,
  TelethonSessionRows,
} from 'opentele2'
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

export async function tdataSurface(account: AccountInput): Promise<void> {
  const draws: Uint8Array[] = [new Uint8Array(32), new Uint8Array(12)]
  const created: TData = await newTdata([account], 'passcode', false, -1, draws)
  created.performanceMode = true
  created.activeIndex = 0
  await saveTdata(created, 'out', false, draws)
  const loaded: TData = await loadTdata('out')
  const migrated: boolean = await migrateTdata(loaded, draws)
  const localKey: Uint8Array = loaded.localKey
  const passcodeKey: Uint8Array = loaded.passcodeKey
  const appVersion: number = loaded.appVersion
  // @ts-expect-error the local key is read-only
  loaded.localKey = localKey
  // @ts-expect-error the performance mode is a boolean
  loaded.performanceMode = 'on'
  // @ts-expect-error draws are byte arrays
  await saveTdata(loaded, 'out', true, ['00'])
  const index: number = addTdataAccount(loaded, 1n, 2, localKey)
  const limit: number = TDATA_MAX_ACCOUNTS
  loaded.keyFile = 'custom'
  // @ts-expect-error the user id is a bigint
  addTdataAccount(loaded, 1, 2, localKey)
  // @ts-expect-error the key file is a string
  loaded.keyFile = 1
  void [migrated, passcodeKey, appVersion, index, limit]
}

export function compatData(tdata: TData): void {
  const newPlan: number[] = drawPlan('new', { hasPasscode: true, performanceMode: false })
  const savePlan: number[] = drawPlan('save', tdata)
  const entries: CatalogEntry[] = catalogEntries('macos')
  const models: string[] = deviceModels('web_a')
  const fields: SessionJsonField[] = sessionJsonFields()
  const fallback: string | null = fields[0].fallback
  const extra: Array<[string, string | boolean | null]> = defaultExtraFields()
  const weights: Record<string, number> = webBrowserWeights()
  const table: string = formatTable(['a'], [['1']], [0])
  const version: string = formatAppVersion(7003001)
  const magic: string = TDF_MAGIC
  // @ts-expect-error the platform is one of the catalog names
  catalogEntries('symbian')
  // @ts-expect-error the operation is new, migrate or save
  drawPlan('delete', tdata)
  // @ts-expect-error a table cell is a string
  formatTable(['a'], [[1]])
  void [newPlan, savePlan, entries, models, fallback, extra, weights, table, version, magic]
}
