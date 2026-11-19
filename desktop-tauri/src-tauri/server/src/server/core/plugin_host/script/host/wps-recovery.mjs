// Persist model recovery separately from usage. A balance success is not a model proof.
import { createHash, randomUUID } from 'node:crypto'

const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex')
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value==='object'
  ? Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])])) : value
export const credential = auth => digest([auth?.metadata?.cookie, auth?.cookie, auth?.key, auth?.access, auth?.metadata?.sid])
const kind = model => 'wpsRecovery.' + digest(model.replace(/@[^@]+$/, '').toLowerCase()).slice(0, 32)
const blocked = () => Object.assign(new Error('WPS 模型等待独立回答验证；余额成功不能恢复'), {code:'account_model_unavailable'})

export class WpsRecovery {
  constructor(rpc, getAuth) { this.rpc=rpc; this.getAuth=getAuth; this.locks=new Map();this.writes=new Map() }
  async mutate(account, fn) {
    const previous=this.writes.get(account) || Promise.resolve()
    let release;const next=new Promise(resolve=>{release=resolve})
    this.writes.set(account,next)
    await previous
    try {return await fn()} finally {release();if(this.writes.get(account)===next)this.writes.delete(account)}
  }
  applies(provider) { return (provider.originalID || provider.id) === 'wps-lingxi' }
  async read(account, model) { return this.rpc('store.ledger_get',{account,kind:kind(model)}) }
  async write(account, model, value) { return this.rpc('store.ledger_put',{account,kind:kind(model),value}) }
  async check(provider, account, model, auth) {
    if (!this.applies(provider) || !account) return
    const identity=await this.read(account,'*')
    if (identity?.blocked && (identity.reason==='verification' || identity.credential===credential(auth))) throw blocked()
    if ((await this.read(account,model))?.blocked) throw blocked()
  }
  async failure(provider, account, model, auth, status, body) {
    if (!this.applies(provider) || !account) return
    const error=body?.error || body
    const verification=status===403 && ['UserIdentityNotVerified','40331'].includes(String(error?.code))
    const reason=verification ? 'verification' : status===401 ? 'authentication' : status===429 ? 'rate'
      : status===403 && error?.code==='PermissionDenied' ? 'permission' : null
    if (!reason) return
    await this.mutate(account,async()=>{
      if (credential(await this.getAuth())!==credential(auth)) return
      const target=(reason==='authentication' || verification)?'*':model
      await this.write(account,target,{blocked:true,reason,model,credential:credential(auth),revision:randomUUID(),at:Date.now()})
    })
  }
  async recover(provider, account, model, probe, expect) {
    if (!this.applies(provider) || !account || typeof model!=='string' || !model.trim()) throw blocked()
    const lock=account+'\n'+kind(model)
    if (this.locks.has(lock)) return {recovered:false,reason:'busy'}
    this.locks.set(lock,true)
    try {
      const auth=await this.getAuth()
      if (expect && digest(canonical(auth))!==digest(canonical(expect))) return {recovered:false,reason:'credential_changed'}
      const identity=await this.read(account,'*')
      if (identity?.blocked && identity.reason==='verification') return {recovered:false,reason:'upstream_identity_verification_required'}
      if (identity?.blocked && identity.credential===credential(auth)) return {recovered:false,reason:'new_login_required'}
      const before=await this.read(account,model)
      if (!before?.blocked) return {recovered:false,reason:'no_model_gate'}
      // A dedicated, bounded request; never replay a customer's conversation.
      const response=await probe(auth)
      const choice=response?.choices?.[0]
      const valid=!response?.error && ['stop','end_turn'].includes(choice?.finish_reason)
        && typeof choice?.message?.content==='string' && !!choice.message.content.trim()
      if (!valid) return {recovered:false,reason:'no_complete_answer'}
      return await this.mutate(account,async()=>{
        if (credential(await this.getAuth())!==credential(auth)) return {recovered:false,reason:'credential_changed'}
        const latest=await this.read(account,model)
        const currentIdentity=await this.read(account,'*')
        if (latest?.revision!==before?.revision || currentIdentity?.revision!==identity?.revision) return {recovered:false,reason:'newer_failure'}
        await this.write(account,model,{blocked:false,credential:credential(auth),revision:randomUUID(),at:Date.now(),proof:'answer_complete'})
        return {recovered:true}
      })
    } finally { this.locks.delete(lock) }
  }
}

export class WpsErrorFrames {
  constructor(note) {this.note=note;this.decoder=new TextDecoder();this.pending=''}
  async push(bytes) {
    this.pending+=this.decoder.decode(bytes,{stream:true})
    if(this.pending.length>2*1024*1024)throw new Error('WPS event exceeded recovery parser limit')
    let end
    while((end=this.pending.indexOf('\n'))>=0) {
      const line=this.pending.slice(0,end).trim();this.pending=this.pending.slice(end+1)
      if(!line.startsWith('data:'))continue
      let frame;try{frame=JSON.parse(line.slice(5))}catch{continue}
      if(frame.error)await this.note(frame.error.status || 502,frame)
    }
  }
}
