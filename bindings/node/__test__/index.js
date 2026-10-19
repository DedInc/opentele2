// index.js: the entry point of `node --test __test__`.
//
// Since Node 21 the test runner treats its arguments as glob patterns, and a
// pattern naming a directory runs that directory as one module, which
// resolves to this file. It imports every *.test.mjs beside it so their
// node:test cases register in this process.

'use strict'

const { readdirSync } = require('node:fs')
const path = require('node:path')
const { pathToFileURL } = require('node:url')

const files = readdirSync(__dirname)
  .filter((name) => name.endsWith('.test.mjs'))
  .sort()

;(async () => {
  for (const name of files) {
    await import(pathToFileURL(path.join(__dirname, name)).href)
  }
})().catch((error) => {
  process.exitCode = 1
  throw error
})
