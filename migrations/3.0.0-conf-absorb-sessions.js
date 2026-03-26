export default function (migration) {
  migration.describe('Move adapt-authoring-sessions config keys to adapt-authoring-auth')

  migration
    .where('adapt-authoring-sessions')
    .mutate(config => {
      const sessions = config['adapt-authoring-sessions']
      const auth = config['adapt-authoring-auth'] ||= {}

      const keyMap = {
        collectionName: 'sessionCollection',
        lifespan: 'sessionLifespan',
        rolling: 'sessionRolling',
        sameSite: 'sessionSameSite',
        secret: 'sessionSecret',
        secure: 'sessionSecure'
      }
      for (const [oldKey, newKey] of Object.entries(keyMap)) {
        if (oldKey in sessions) {
          auth[newKey] = sessions[oldKey]
          delete sessions[oldKey]
        }
      }

      if (!Object.keys(sessions).length) {
        delete config['adapt-authoring-sessions']
      }
    })
}
