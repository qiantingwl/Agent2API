// Preserve the source gateway's shared identity limit for duplicate source rows.
const groups = new Map()

export async function acquireMigrationSlot(metadata, signal) {
  const key = metadata?.migrationConcurrencyGroup
  const limit = metadata?.migrationConcurrencyLimit
  if (typeof key !== 'string' || !key || !Number.isSafeInteger(limit) || limit <= 0) return () => {}
  signal?.throwIfAborted()
  let group = groups.get(key)
  if (!group) groups.set(key, group = { active: 0, waiting: [] })
  const pump = () => {
    while (group.waiting.length && group.active < limit) {
      const next = group.waiting.shift()
      next.signal?.removeEventListener('abort', next.abort)
      group.active++
      let released = false
      next.resolve(() => {
        if (released) return
        released = true
        group.active--
        pump()
      })
    }
    if (!group.active && !group.waiting.length) groups.delete(key)
  }
  return new Promise((resolve, reject) => {
    const waiter = { resolve, signal, abort: null }
    waiter.abort = () => {
      const index = group.waiting.indexOf(waiter)
      if (index < 0) return
      group.waiting.splice(index, 1)
      reject(signal.reason)
      pump()
    }
    group.waiting.push(waiter)
    signal?.addEventListener('abort', waiter.abort, { once: true })
    pump()
  })
}

export function releaseAfterBody(response, release, signal) {
  if (!response.body) { release(); return response }
  const reader = response.body.getReader()
  let finished = false
  const finish = () => {
    if (finished) return
    finished = true
    signal?.removeEventListener('abort', abort)
    release()
  }
  const abort = () => { void reader.cancel(signal.reason).catch(() => {}).finally(finish) }
  signal?.addEventListener('abort', abort, { once: true })
  if (signal?.aborted) abort()
  const body = new ReadableStream({
    async pull(controller) {
      try {
        const next = await reader.read()
        if (next.done) { finish(); controller.close() }
        else controller.enqueue(next.value)
      } catch (error) { finish(); controller.error(error) }
    },
    async cancel(reason) { try { await reader.cancel(reason) } finally { finish() } },
  })
  return new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers })
}
