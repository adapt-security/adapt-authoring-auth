export default function (migration) {
  migration.describe('Move adapt-authoring-sessions config keys to adapt-authoring-auth')

  migration
    .where('adapt-authoring-sessions')
    .replace('collectionName', 'adapt-authoring-auth', 'sessionCollection')
    .replace('lifespan', 'adapt-authoring-auth', 'sessionLifespan')
    .replace('rolling', 'adapt-authoring-auth', 'sessionRolling')
    .replace('sameSite', 'adapt-authoring-auth', 'sessionSameSite')
    .replace('secret', 'adapt-authoring-auth', 'sessionSecret')
    .replace('secure', 'adapt-authoring-auth', 'sessionSecure')
}
