import test from 'node:test'
import assert from 'node:assert/strict'
import { _internal } from '../index.mjs'

const { normalizeUsage, LingxiTranslator, foldFrames } = _internal
test('maintenance expires login only with authentication evidence', () => {
  for (const status of [400, 402, 403, 409, 422, 429, 502]) {
    assert.equal(_internal.loginExpired({ status, upstreamCode: 'PermissionDenied' }), false)
  }
  assert.equal(_internal.loginExpired({ status: 401 }), true)
  for (const code of ['Unauthorized', 'UserUnauthorized']) {
    assert.equal(_internal.loginExpired({ status: 200, upstreamCode: code }), true)
    assert.equal(_internal.loginExpired({ status: 403, upstreamCode: code }), true)
  }
})
test('HTTP 200 structured unauthorized envelopes retain their authentication classification', () => {
  for (const payload of [{ code: 'UserUnauthorized' }, { result: 'UserUnauthorized' },
    { error: 'UserUnauthorized' }, { result: { code: 'UserUnauthorized' } },
    { data: { result: 'UserUnauthorized' } }, { error: { code: 'UserUnauthorized' } }]) {
    assert.equal(_internal.businessErrorStatus(_internal.upstreamErrorCode(payload)), 401)
  }
  assert.equal(_internal.upstreamErrorCode({ result: 'Success', data: { text: 'UserUnauthorized' } }), '')
})
test('partial cumulative usage preserves omitted counters and does not add snapshots', () => {
  let usage = normalizeUsage({ prompt_tokens: 200, cached_tokens: 150 })
  usage = normalizeUsage({ completion_tokens: 12, reasoning_tokens: 3 }, usage)
  usage = normalizeUsage({ completion_tokens: 15 }, usage)
  assert.deepEqual(usage, { prompt_tokens: 200, completion_tokens: 15, total_tokens: 215,
    prompt_tokens_details: { cached_tokens: 150 }, completion_tokens_details: { reasoning_tokens: 3 } })
})
test('explicit zero clears cache while missing, invalid and null counters do not', () => {
  const first = normalizeUsage({ prompt_tokens: 200, cached_tokens: 150 })
  for (const value of [undefined, null, '', -1, Infinity, 'invalid']) {
    assert.equal(normalizeUsage({ cached_tokens: value }, first).prompt_tokens_details.cached_tokens, 150)
  }
  assert.equal(normalizeUsage({ prompt_tokens_details: { cached_tokens: 0 } }, first).prompt_tokens_details.cached_tokens, 0)
})
test('independent translators do not inherit the failed attempt usage', () => {
  const failed = new LingxiTranslator('model')
  failed.push('data: {"usage":{"prompt_tokens":200,"cached_tokens":150}}\n\n')
  assert.throws(() => failed.push('data: {"error":{"message":"failed"}}\n\n'))
  const successful = new LingxiTranslator('model')
  const frames = successful.push('data: {"choices":[{"text":"ok"}],"usage":{"prompt_tokens":20}}\n\ndata: {"choices":[{"finish_reason":"stop"}],"usage":{"completion_tokens":2}}\n\n')
  frames.push(...successful.finish())
  assert.deepEqual(foldFrames(frames).usage, { prompt_tokens: 20, completion_tokens: 2, total_tokens: 22 })
})
test('split usage survives streaming translation and nonstream aggregation', () => {
  const translator = new LingxiTranslator('model')
  const frames = translator.push('data: {"choices":[{"text":"ok"}],"usage":{"prompt_tokens":200,"cached_tokens":150}}\n\ndata: {"choices":[{"finish_reason":"stop"}],"usage":{"completion_tokens":12}}\n\n')
  frames.push(...translator.finish())
  const result = foldFrames(frames)
  assert.equal(result.usage.prompt_tokens_details.cached_tokens, 150)
  assert.equal(result.usage.total_tokens, 212)
})
test('error wins over finish in the same frame', () => {
  const translator = new LingxiTranslator('model')
  translator.push('data: {"choices":[{"text":"partial"}]}\n\n')
  assert.throws(() => translator.push('data: {"error":{"message":"failed"},"choices":[{"finish_reason":"stop"}]}\n\n'))
  assert.deepEqual(translator.finish(), [])
})
test('terminal-only stream is not successful output', () => {
  const translator = new LingxiTranslator('model')
  assert.throws(() => translator.push('data: {"choices":[{"finish_reason":"stop"}]}\n\n'), /有效/)
})
test('usage after finish_reason is consumed before emitting success', () => {
  const translator = new LingxiTranslator('model')
  const early = translator.push('data: {"choices":[{"text":"ok","finish_reason":"stop"}],"usage":{"prompt_tokens":200}}\n\n')
  assert.ok(!early.join('').includes('[DONE]'))
  translator.push('data: {"usage":{"cached_tokens":150,"completion_tokens":12}}\n\n')
  const tail = translator.finish()
  assert.equal(foldFrames(tail).usage.prompt_tokens_details.cached_tokens, 150)
  assert.equal(foldFrames(tail).usage.total_tokens, 212)
  assert.equal(tail.filter(frame => frame.includes('[DONE]')).length, 1)
  assert.deepEqual(translator.finish(), [])
})
test('an error after finish_reason cannot become a successful DONE', () => {
  const translator = new LingxiTranslator('model')
  const early = translator.push('data: {"choices":[{"text":"partial","finish_reason":"stop"}]}\n\n')
  assert.ok(!early.join('').includes('[DONE]'))
  assert.throws(() => translator.push('data: {"result":"UserUnauthorized"}\n\n'), error => error.status === 401)
  assert.deepEqual(translator.finish(), [])
})
test('whitespace, truncated output and bare DONE are not complete answers', () => {
  for (const input of ['data: [DONE]\n\n', 'data: {"choices":[{"text":"partial"}]}\n\n',
    'data: {"choices":[{"text":"  "}]}\n\ndata: [DONE]\n\n']) {
    const translator = new LingxiTranslator('model')
    translator.push(input)
    assert.throws(() => translator.finish())
  }
})
test('task and chat recovery never override auth, permission, quota or conflict errors', () => {
  for (const status of [401, 402, 403, 409, 422, 429]) {
    assert.equal(_internal.canRebuildRun({ status, message: 'session not found' }), false)
  }
  assert.equal(_internal.canRebuildRun({ status: 404, message: 'session not found' }), true)
  assert.equal(_internal.canRebuildRun({ status: 502, message: 'network failed' }), false)
})
