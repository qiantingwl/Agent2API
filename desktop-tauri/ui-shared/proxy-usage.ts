export type ProxyService = 'update' | 'kernel'

export type ProxyUsage = {
  usedBy?: Array<{ id?: string; name?: string; enabled?: boolean }>
  usedByServices?: ProxyService[]
}

export function hasProxyUsage(item: ProxyUsage): boolean {
  return Boolean(item.usedBy?.length || item.usedByServices?.length)
}

export function proxyServiceLabels(item: ProxyUsage, t: (key: string) => string): string[] {
  return [...new Set(item.usedByServices || [])]
    .filter(service => service === 'update' || service === 'kernel')
    .map(service => t(service === 'kernel' ? '代理内核下载' : '软件 / 插件更新'))
}
