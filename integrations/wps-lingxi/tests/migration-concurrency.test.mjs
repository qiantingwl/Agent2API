import test from 'node:test'
import assert from 'node:assert/strict'
import { acquireMigrationSlot, releaseAfterBody } from '../migration-concurrency.mjs'

test('duplicate source rows share one upstream slot, other groups stay independent', async () => {
  const config = { migrationConcurrencyGroup: 'source-group', migrationConcurrencyLimit: 1 }
  const first = await acquireMigrationSlot(config)
  let admitted = false
  const second = acquireMigrationSlot(config).then(release => { admitted = true; return release })
  await Promise.resolve()
  assert.equal(admitted, false)
  const other = await acquireMigrationSlot({ ...config, migrationConcurrencyGroup: 'independent' })
  other(); first(); first()
  const release = await second
  assert.equal(admitted, true)
  release()
})

test('cancelled waiter does not consume the next slot', async () => {
  const config = { migrationConcurrencyGroup: 'cancel-wait', migrationConcurrencyLimit: 1 }
  const first = await acquireMigrationSlot(config)
  const controller = new AbortController()
  const pending = acquireMigrationSlot(config, controller.signal)
  controller.abort()
  await assert.rejects(pending, { name: 'AbortError' })
  first()
  const next = await acquireMigrationSlot(config)
  next()
})

test('slot lasts through streaming and releases on completion', async () => {
  let count = 0
  const response = releaseAfterBody(new Response('answer'), () => count++)
  assert.equal(count, 0)
  assert.equal(await response.text(), 'answer')
  assert.equal(count, 1)
})

test('body cancellation cancels upstream and releases once', async () => {
  let count = 0, cancelled = false
  const body = new ReadableStream({ cancel() { cancelled = true } })
  const response = releaseAfterBody(new Response(body), () => count++)
  await response.body.cancel()
  assert.equal(cancelled, true)
  assert.equal(count, 1)
})

test('aborting a live response cancels its reader and releases the slot', async () => {
  let count = 0, cancelled = false
  const controller = new AbortController()
  const body = new ReadableStream({ cancel() { cancelled = true } })
  const response = releaseAfterBody(new Response(body), () => count++, controller.signal)
  controller.abort()
  await response.text()
  assert.equal(cancelled, true)
  assert.equal(count, 1)
})
