import * as React from 'react'
import { Button, Card, CardContent, CardHeader, Input, Label, Switch } from '@ui'

type Settings = { enabled: boolean; minSeconds: number; maxSeconds: number }

async function request(method: string, body: unknown = null): Promise<Settings> {
  const bridge = (window as unknown as { __TAURI_INTERNALS__?: {
    invoke: (command: string, args: unknown) => Promise<unknown>
  } }).__TAURI_INTERNALS__
  if (!bridge) throw new Error('配置连接不可用')
  const response = await bridge.invoke('api_request', {
    request: { method, path: '/api/config', body },
  }) as { success?: boolean; error?: string; data?: { quickPlaceholder?: Settings } }
  if (response.success === false || !response.data?.quickPlaceholder) {
    throw new Error(response.error || '读取占位设置失败')
  }
  return response.data.quickPlaceholder
}

export function QuickPlaceholderSettings() {
  const [value, setValue] = React.useState<Settings | null>(null)
  const [busy, setBusy] = React.useState(false)
  const [message, setMessage] = React.useState('正在读取…')
  React.useEffect(() => {
    let active = true
    void request('GET').then(settings => {
      if (active) { setValue(settings); setMessage('') }
    }).catch(error => { if (active) setMessage(String(error.message)) })
    return () => { active = false }
  }, [])
  const save = async () => {
    if (!value) return
    if (!Number.isInteger(value.minSeconds) || !Number.isInteger(value.maxSeconds)
      || value.minSeconds < 0 || value.maxSeconds > 120 || value.minSeconds > value.maxSeconds) {
      setMessage('请输入 0–120 秒的整数，下限不能大于上限'); return
    }
    setBusy(true)
    try { setValue(await request('PUT', { quickPlaceholder: value })); setMessage('已保存，对新请求生效') }
    catch (error) { setMessage(error instanceof Error ? error.message : '保存失败') }
    finally { setBusy(false) }
  }
  return <Card render={<section />} className='panel'>
    <CardHeader><h3>流式占位</h3></CardHeader>
    <CardContent className='panel-body'>
      <div className='settings-switches'>
        <Label htmlFor='quick-placeholder-enabled'>等待回答时发送空白占位</Label>
        <Switch id='quick-placeholder-enabled' checked={value?.enabled ?? false}
          disabled={!value || busy} onCheckedChange={enabled => value && setValue({ ...value, enabled })} />
      </div>
      <div className='settings-switches'>
        <Label htmlFor='quick-placeholder-min'>最短等待（秒）</Label>
        <Input id='quick-placeholder-min' type='number' min={0} max={120} step={1}
          value={value?.minSeconds ?? ''} disabled={!value || busy}
          onChange={event => value && setValue({ ...value, minSeconds: Number(event.currentTarget.value) })} />
        <Label htmlFor='quick-placeholder-max'>最长等待（秒）</Label>
        <Input id='quick-placeholder-max' type='number' min={0} max={120} step={1}
          value={value?.maxSeconds ?? ''} disabled={!value || busy}
          onChange={event => value && setValue({ ...value, maxSeconds: Number(event.currentTarget.value) })} />
      </div>
      <p className='hint'>每次请求在范围内随机等待；上下限相同则固定等待。回答先到会直接返回。</p>
      <Button disabled={!value || busy} onClick={() => void save()}>保存占位设置</Button>
      <p role='status'>{message}</p>
    </CardContent>
  </Card>
}
