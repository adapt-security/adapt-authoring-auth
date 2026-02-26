import { readFile } from 'node:fs/promises'
import path from 'node:path'

export async function loadRouteConfig (rootDir, target, options = {}) {
  const filePath = path.join(rootDir, 'routes.json')
  let raw
  try {
    raw = await readFile(filePath, 'utf8')
  } catch (e) {
    if (e.code === 'ENOENT') return null
    throw e
  }
  const config = JSON.parse(raw)
  const aliases = options.handlerAliases || {}
  if (Array.isArray(config.routes)) {
    config.routes = config.routes.map(routeDef => {
      const resolved = { ...routeDef }
      if (routeDef.handlers) {
        resolved.handlers = Object.fromEntries(
          Object.entries(routeDef.handlers).map(([method, handlerStr]) => {
            if (Object.hasOwn(aliases, handlerStr)) {
              return [method, aliases[handlerStr]]
            }
            if (typeof target[handlerStr] !== 'function') {
              throw new Error(`Cannot resolve handler '${handlerStr}': no such method on target`)
            }
            return [method, target[handlerStr].bind(target)]
          })
        )
      }
      return resolved
    })
  }
  return config
}
