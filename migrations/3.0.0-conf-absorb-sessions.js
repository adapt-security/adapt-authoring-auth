export default function (migration) {
  migration.describe('Move adapt-authoring-sessions config into adapt-authoring-auth')

  const keyMap = {
    collectionName: 'sessionCollection',
    lifespan: 'sessionLifespan',
    rolling: 'sessionRolling',
    sameSite: 'sessionSameSite',
    secret: 'sessionSecret',
    secure: 'sessionSecure'
  }

  migration.run(async ({ readFile, writeFile, log }) => {
    let raw
    try {
      raw = await readFile(`conf/${process.env.NODE_ENV}.config.js`)
    } catch (e) {
      log('info', 'No config file found, skipping')
      return
    }
    const sessionMatch = raw.match(/['"]adapt-authoring-sessions['"]\s*:\s*\{/)
    if (!sessionMatch) {
      log('info', 'No adapt-authoring-sessions config found, skipping')
      return
    }
    // dynamically import the config to read values
    const configPath = `conf/${process.env.NODE_ENV}.config.js`
    const absPath = await import('path').then(p => p.resolve(process.cwd(), configPath))
    const config = (await import(absPath)).default

    const sessionConfig = config['adapt-authoring-sessions']
    if (!sessionConfig || !Object.keys(sessionConfig).length) {
      return
    }
    const authConfig = config['adapt-authoring-auth'] || {}
    for (const [oldKey, newKey] of Object.entries(keyMap)) {
      if (oldKey in sessionConfig) {
        authConfig[newKey] = sessionConfig[oldKey]
        log('info', `Moved adapt-authoring-sessions.${oldKey} to adapt-authoring-auth.${newKey}`)
      }
    }
    config['adapt-authoring-auth'] = authConfig
    delete config['adapt-authoring-sessions']

    const output = `export default ${JSON.stringify(config, null, 2)}\n`
    await writeFile(`conf/${process.env.NODE_ENV}.config.js`, output)
    log('info', 'Session config migrated to adapt-authoring-auth')
  })
}
