# Creating auth plugins

> Preliminary reading: [Authentication and permissions](auth-permissions.md) — Overview of the auth system
---

Auth plugins allows for implementations of different authentication methods.

## Basic structure

Extend `AbstractAuthModule` and implement the required methods:

```javascript
import { AbstractAuthModule } from 'adapt-authoring-auth'

class MyAuthModule extends AbstractAuthModule {
  async setValues () {
    this.type = 'myauth'           // Unique identifier
    this.userSchema = 'myauthuser' // Optional custom user schema
  }
  
  async authenticate (user, req, res) {
    // Verify credentials - throw on failure
  }
}
```

## Reference

### Required values

| Property | Description |
| -------- | ----------- |
| `this.type` | Unique identifier for the auth type (e.g., `'local'`, `'github'`) |

### Optional values

| Property | Default | Description |
| -------- | ------- | ----------- |
| `this.userSchema` | `'user'` | Schema name for validating users of this auth type - allows custom data to be added to users |
| `this.routes` | `[]` | Additional routes for the auth plugin |

### Inherited methods

| Method | Description |
| ------ | ----------- |
| `register(data)` | Register a new user with this auth type |
| `setUserEnabled(user, isEnabled)` | Enable or disable a user account |
| `disavowUser(query)` | Revoke user tokens |
| `secureRoute(route, method, scopes)` | Secure a route |
| `unsecureRoute(route, method)` | Remove auth from a route |
| `comparePassword(plain, hashed)` | Compare a plain password against a hash |

### Hooks

| Hook | Description |
| ---- | ----------- |
| `registerHook` | Invoked when a new user registers (mutable) |

## Worked Example: GitHub OAuth

We will work through an example authentication plugin using GitHub OAuth.

For OAuth providers (GitHub, Okta, Google, etc.), the flow redirects users to the provider rather than validating credentials directly.

### Key steps for OAuth plugins

1. Extend `AbstractAuthModule` and set `this.type` to a unique identifier
2. Add config & user schemas (if necessary)
3. Use Passport.js with the appropriate strategy for your provider
4. The OAuth callback should generate a token and store it in the session
5. Mark OAuth routes as unsecured since users aren't authenticated yet
6. Handle user registration if the OAuth profile doesn't match an existing user
7. Add UI code for your plugin, and register it with the UI module (see [this page](ui-extensions))

**Below code is for illustrative purposes only, and is not guaranteed to work without modifications**

### Creating Auth Module

```javascript
import { AbstractAuthModule, AuthToken } from 'adapt-authoring-auth'
import passport from 'passport'
import { Strategy as GitHubStrategy } from 'passport-github2'

class GitHubAuthModule extends AbstractAuthModule {
  async setValues () {
    this.type = 'github'
    this.userSchema = 'githubauthuser'
  }
  
  async init () {
    await super.init()
    const [server, users] = await this.app.waitForModule('server', 'users', 'sessions')
    
    this.router.expressRouter.use(passport.initialize())
    this.router.expressRouter.use(passport.session())
    
    passport.use(new GitHubStrategy({
      clientID: this.getConfig('clientID'),
      clientSecret: this.getConfig('clientSecret'),
      callbackURL: `//${server.getConfig('host')}:${server.getConfig('port')}${this.router.path}/callback`
    }, async (accessToken, refreshToken, profile, done) => {
      try {
        // Find user by any of their GitHub emails
        let [user] = await users.find({ 
          $or: profile.emails.map(({ value }) => ({ email: value })) 
        })
        
        if (!user && this.getConfig('registerUserWithRoles').length) {
          user = await this.registerUser(profile)
        }
        
        return done(null, user || false)
      } catch (e) {
        return done(e)
      }
    }))
    
    passport.serializeUser((user, done) => done(null, user))
    passport.deserializeUser((obj, done) => done(null, obj))
    
    // OAuth flow: redirect to provider, then handle callback
    this.router.addRoute({
      route: '/',
      handlers: { get: passport.authenticate('github', { scope: ['user:email'] }) }
    }, {
      route: '/callback',
      handlers: { get: passport.authenticate('github', { failureRedirect: '/' }) }
    }, {
      route: '/callback',
      handlers: { get: this.onAuthenticated.bind(this) }
    })
    
    this.unsecureRoute('/', 'get')
    this.unsecureRoute('/callback', 'get')
  }
  
  async registerUser (profile) {
    const email = profile.emails[0].value
    const nameParts = profile.displayName.split(' ')
    const roles = await this.app.waitForModule('roles')
    const roleNames = this.getConfig('registerUserWithRoles')
    const matchedRoles = await roles.find({ 
      $or: roleNames.map(shortName => ({ shortName })) 
    })
    
    return this.register({
      email,
      firstName: nameParts[0] || profile.displayName,
      lastName: nameParts[1] || '',
      roles: matchedRoles.map(r => r._id.toString())
    })
  }
  
  async onAuthenticated (req, res, next) {
    try {
      req.session.token = await AuthToken.generate(this.type, req.user)
      res.redirect('/')
    } catch (e) {
      return next(e)
    }
  }
}
```

### Adding UI login support

For OAuth plugins, you may need to override the default login behaviour to redirect to the provider instead of showing a login form.

Create a UI plugin:

```javascript
// plugins/myauth/index.js
define(function (require) {
  const Origin = require('core/origin')
  
  Origin.on('router:handleLogin', function () {
    // Redirect to OAuth provider
    window.location = window.origin + '/api/auth/myauth'
  })
})
```

Register the UI plugin in your module's `init` method:

```javascript
async init () {
  await super.init()
  
  const ui = await this.app.waitForModule('ui')
  ui.addUiPlugin(path.resolve(this.rootDir, 'plugins'))
}
```
