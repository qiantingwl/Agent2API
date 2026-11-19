import { test } from 'node:test'
import assert from 'node:assert/strict'
import { WPSLingxiAuthPlugin, _internal as wps } from '../index.mjs'

test('affinity separates conversation, credential version, model and system prefix', () => {
  const key = (cookie='cookie-a', model='model-a', session='session-a', text='system-a') =>
    wps.conversationKey(cookie, model, session, {messages:[{role:'system',content:text}]})
  assert.equal(key(), key())
  assert.notEqual(key(), key('cookie-b'))
  assert.notEqual(key(), key('cookie-a', 'model-b'))
  assert.notEqual(key(), key('cookie-a', 'model-a', 'session-b'))
  assert.notEqual(key(), key('cookie-a', 'model-a', 'session-a', 'system-b'))
  assert.notEqual(key('cookie-a', 'model-a', ''), key('cookie-a', 'model-a', ''))
})

test('run cache expires entries and stays bounded at large account counts', () => {
  wps.runs.clear()
  wps.cacheRun('expired', {at:0})
  for (let i=0; i<4100; i++) wps.cacheRun(String(i), {at:Date.now()})
  assert.equal(wps.runs.size, 4096)
  assert.equal(wps.runs.has('expired'), false)
  wps.runs.clear()
})

test('business errors keep their original status; generic 403 never becomes expired login', () => {
  for (const status of [400,401,402,403,404,409,422,429,502,504]) {
    assert.equal(wps.chatErrorStatus({status,message:'cookie access denied'}), status)
  }
})

const sessionPath = '/api/aioffice/v1/cowork/sessions'
const runPath = '/api/public/v1/credits/runs'
const chatPath = '/api/public/v1/agent-runtime/chat/completions'
let sequence = 0
async function withUpstream(phase, reply, body, verify) {
  const plugin = await WPSLingxiAuthPlugin()
  const loader = await plugin.auth.loader(async () => ({cookie: 'wps_sid=' + 'synthetic'.repeat(5)}))
  const original = globalThis.fetch
  const paths = []
  globalThis.fetch = async (url, init) => {
    const path = new URL(url).pathname
    paths.push(path)
    if (path === phase) return reply(init)
    if (path === sessionPath) return Response.json({code:'Success',data:{session_id:'synthetic-session'}})
    if (path === runPath) return Response.json({code:'Success',data:{run_id:'synthetic-run'}})
    throw new Error('Unexpected synthetic route')
  }
  try {
    const response = await loader.fetch('https://mock/chat/completions', {
      body: JSON.stringify({model:'gateway-test-'+(++sequence), messages:[{role:'user',content:'synthetic'}], ...body}),
    })
    await verify(response, await response.text(), paths)
  } finally {globalThis.fetch=original}
}

for (const phase of [sessionPath, runPath, chatPath]) {
  test(`ResourceConflict at ${phase} preserves 409 and code without domain fallback or replay`, async () => {
    await withUpstream(phase, () => Response.json({code:'ResourceConflict',message:'session not found'}, {status:409}), {},
      (response,text,paths) => {
        assert.equal(response.status,409)
        assert.equal(JSON.parse(text).error.code,'ResourceConflict')
        assert.equal(paths.filter(p=>p===phase).length,1)
      })
  })
}

for (const [code,status] of [['ResourceConflict',409],['InvalidArgument',400],['UserIdentityNotVerified',403],[40331,403]]) {
  test(`HTTP 200 structured ${code} is returned as ${status} during session creation`, async () => {
    await withUpstream(sessionPath, () => Response.json({error:{code,message:'synthetic error'}}), {},
      (response,text,paths) => {
        assert.equal(response.status,status)
        assert.equal(JSON.parse(text).error.code,String(code))
        assert.equal(paths.length,1)
      })
  })
  for (const stream of [false,true]) {
    test(`SSE ${code}, streaming=${stream}, preserves classification and never completes successfully`, async () => {
      await withUpstream(chatPath, () => new Response(
        'data: '+JSON.stringify({code:'Success',choices:[{text:'partial'}]})+'\n\n'+
        'data: '+JSON.stringify({error:{code,message:'synthetic error'}})+'\n\n',
        {headers:{'content-type':'text/event-stream'}}), {stream},
      (response,text,paths) => {
        assert.equal(response.status,stream ? 200 : status)
        if (stream) {
          assert.match(text, /"content":"partial"/)
          assert.match(text, new RegExp('"status":'+status))
          assert.doesNotMatch(text,/\[DONE\]|"finish_reason":"stop"/)
        } else assert.equal(JSON.parse(text).error.code,String(code))
        assert.equal(paths.filter(p=>p===chatPath).length,1)
      })
    })
  }
}

for (const stream of [false,true]) {
  test(`empty final frame is an error, streaming=${stream}`, async () => {
    await withUpstream(chatPath, () => new Response('data: '+JSON.stringify({code:'Success',choices:[{text:'  ',finish_reason:'stop'}]})+'\n\n'), {stream},
      (response,text) => {
        assert.equal(response.status,stream ? 200 : 502)
        assert.match(text,/"error"/)
        assert.doesNotMatch(text,/\[DONE\]|"finish_reason":"stop"/)
      })
  })
}

test('parallel run creation within one millisecond keeps unique decimal request IDs', async () => {
  const originalFetch = globalThis.fetch
  const originalNow = Date.now
  const ids = new Set()
  const plugin = await WPSLingxiAuthPlugin()
  const loader = await plugin.auth.loader(async () => ({cookie:'wps_sid='+'synthetic'.repeat(5)}))
  Date.now = () => 1795075200000
  globalThis.fetch = async (url, init) => {
    const path = new URL(url).pathname
    if (path===sessionPath) return Response.json({code:'Success',data:{session_id:'synthetic-session'}})
    if (path===runPath) {
      const id = JSON.parse(init.body).client_request_id
      assert.match(id,/^\d+$/)
      if (ids.has(id)) return Response.json({code:'ResourceConflict',message:'资源已存在'},{status:409})
      ids.add(id)
      return Response.json({code:'Success',data:{run_id:'synthetic-run-'+id}})
    }
    if (path===chatPath) return new Response('data: '+JSON.stringify({code:'Success',choices:[{text:'ok',finish_reason:'stop'}]})+'\n\n')
    throw new Error('Unexpected synthetic route')
  }
  try {
    const replies = await Promise.all(Array.from({length:64},(_,i)=>loader.fetch('https://mock/chat/completions',{
      body:JSON.stringify({model:'concurrent-'+i,stream:false,messages:[{role:'user',content:'synthetic'}]}),
    })))
    for (const response of replies) {
      assert.equal(response.status,200)
      assert.equal((await response.json()).choices[0].message.content,'ok')
    }
    assert.equal(ids.size,64)
  } finally {Date.now=originalNow;globalThis.fetch=originalFetch}
})

test('quota 403 and missing balance do not mark credentials expired or invent zero balance', async () => {
  const original=globalThis.fetch
  const plugin=await WPSLingxiAuthPlugin()
  const auth=async()=>({type:'api',key:'wps_sid='+'synthetic-sid'.repeat(3)})
  try {
    globalThis.fetch=async()=>new Response('{}',{status:403})
    const denied=await plugin.auth.usage(auth)
    assert.equal(denied.signIn,'kept')
    assert.ok(denied.error)
    globalThis.fetch=async()=>Response.json({code:'Success',data:{}})
    const absent=await plugin.auth.usage(auth)
    assert.ok(absent.error)
    assert.equal(absent.balance,undefined)
  } finally {globalThis.fetch=original}
})
