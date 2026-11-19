import test from 'node:test'
import assert from 'node:assert/strict'
import { WpsRecovery, WpsErrorFrames } from '../../../desktop-tauri/src-tauri/server/src/server/core/plugin_host/script/host/wps-recovery.mjs'

const provider = {id:'wps-lingxi'}
const complete = () => ({choices:[{finish_reason:'stop',message:{content:'verified'}}]})
function fixture() {
  const rows = new Map()
  let auth = {cookie:'in-memory-credential'}
  const recovery = new WpsRecovery(async (method, {account,kind,value}) => {
    const key=account+':'+kind
    if (method==='store.ledger_get') return rows.get(key)
    assert.equal(method,'store.ledger_put')
    rows.set(key,value)
  }, async () => auth)
  return {recovery,rows,getAuth:()=>auth,setAuth:value=>{auth=value}}
}
async function fail(f, model='model-a', status=403, code='PermissionDenied') {
  await f.recovery.failure(provider,'reference',model,f.getAuth(),status,{error:{code}})
}

test('WPS model recovery requires a complete nonempty answer and leaves other models gated', async () => {
  const f=fixture()
  await fail(f)
  await fail(f,'model-b',429,'RateLimitExceeded')
  for (const response of [{}, {choices:[{finish_reason:'stop',message:{content:'  '}}]},
    {choices:[{finish_reason:'length',message:{content:'truncated'}}]},
    {...complete(),error:{message:'failed'}}]) {
    assert.equal((await f.recovery.recover(provider,'reference','model-a',async()=>response)).reason,'no_complete_answer')
    await assert.rejects(f.recovery.check(provider,'reference','model-a',f.getAuth()))
  }
  assert.deepEqual(await f.recovery.recover(provider,'reference','model-a',async()=>complete()),{recovered:true})
  await f.recovery.check(provider,'reference','model-a',f.getAuth())
  await assert.rejects(f.recovery.check(provider,'reference','model-b',f.getAuth()))
})

test('WPS identity verification cannot be bypassed by credential changes or model recovery', async () => {
  const f=fixture()
  await fail(f)
  await fail(f,'model-a',403,'UserIdentityNotVerified')
  f.setAuth({cookie:'changed-in-memory-credential'})
  let calls=0
  assert.equal((await f.recovery.recover(provider,'reference','model-a',async()=>{calls++;return complete()})).reason,'upstream_identity_verification_required')
  await assert.rejects(f.recovery.check(provider,'reference','model-a',f.getAuth()))
  assert.equal(calls,0)
})

test('WPS authentication needs new credentials before an independent model proof', async () => {
  const f=fixture()
  await fail(f)
  await fail(f,'model-a',401,'Unauthorized')
  let calls=0
  assert.equal((await f.recovery.recover(provider,'reference','model-a',async()=>{calls++;return complete()})).reason,'new_login_required')
  assert.equal(calls,0)
  f.setAuth({cookie:'changed-in-memory-credential'})
  assert.deepEqual(await f.recovery.recover(provider,'reference','model-a',async()=>complete()),{recovered:true})
  await f.recovery.check(provider,'reference','model-a',f.getAuth())
})

test('WPS a successful old probe cannot clear a newer failure or changed credentials', async () => {
  for (const change of ['failure','identity','credentials']) {
    const f=fixture()
    await fail(f)
    const result=await f.recovery.recover(provider,'reference','model-a',async()=>{
      if (change==='failure') await fail(f)
      if (change==='identity') await fail(f,'model-a',401,'Unauthorized')
      if (change==='credentials') f.setAuth({cookie:'changed-in-memory-credential'})
      return complete()
    })
    assert.equal(result.recovered,false)
    assert.equal(result.reason,change==='credentials'?'credential_changed':'newer_failure')
    assert.equal((await f.recovery.read('reference','model-a')).blocked,true)
  }
})

test('WPS model probe enforces expected credentials and one probe per account/model', async () => {
  const f=fixture()
  await fail(f)
  let release
  const wait=new Promise(resolve=>{release=resolve})
  const active=f.recovery.recover(provider,'reference','model-a',async()=>{await wait;return complete()})
  assert.equal((await f.recovery.recover(provider,'reference','model-a',async()=>complete())).reason,'busy')
  release()
  assert.equal((await active).recovered,true)
  await fail(f)
  let calls=0
  assert.equal((await f.recovery.recover(provider,'reference','model-a',async()=>{calls++;return complete()},{cookie:'old-in-memory-credential'})).reason,'credential_changed')
  assert.equal(calls,0)
})

test('WPS generic permission, quota and transport statuses never create authentication gates', async () => {
  const f=fixture()
  for (const status of [400,402,403,409,502,504]) await fail(f,'model-a',status,'Unclassified')
  assert.equal(f.rows.size,0)
})

test('WPS recovery parser catches split error frames without treating content as errors', async () => {
  const seen=[]
  const frames=new WpsErrorFrames(async(status,body)=>seen.push([status,body.error.code]))
  const encoder=new TextEncoder()
  await frames.push(encoder.encode('data: {"choices":[{"delta":{"content":"error"}}]}\n\ndata: {"err'))
  await frames.push(encoder.encode('or":{"status":401,"code":"Unauthorized"}}\n\ndata: [DONE]\n\n'))
  assert.deepEqual(seen,[[401,'Unauthorized']])
})
