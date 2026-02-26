# Authentication and permissions

The Adapt authoring tool uses a token-based authentication system with role-based access control (RBAC) provided through permissions scopes. This guide covers how authentication works, how to configure authorisation, and how to manage permissions.

## Authentication

Authentication verifies user identity. The system supports multiple authentication methods through plugins (local username/password, OAuth providers like GitHub or Okta, etc.).

### How authentication works

1. User submits credentials to an auth plugin endpoint (e.g., `POST /api/auth/local`)
2. The auth plugin validates the credentials
3. On success, a JWT ([JSON Web Token](https://www.jwt.io/introduction#what-is-json-web-token)) is generated and returned to the client
4. The client includes the token in subsequent requests via the `Authorization` header
5. The server validates the token and checks permissions for each request

### Request auth data

Authenticated requests have auth data attached to `req.auth`:

```javascript
async myHandler (req, res, next) {
  const {
    user,           // The authenticated user document
    scopes,         // Array of permission scopes
    isSuper,        // Whether user has super privileges
    token,          // The decoded JWT
    userSchemaName  // Schema used for the user
  } = req.auth
}
```

### Making authenticated requests

Include the JWT in the `Authorization` header:

```
Authorization: Bearer <token>
```

### Checking authentication status

Retrieve the current user's details and permissions if authenticated (error if not):

```
GET /api/auth/check
```

### Generating tokens

For API integrations etc. tokens can be generated manually with custom lifespans:

> Requires the `generatetoken:auth` scope

```
POST /api/auth/generatetoken
Content-Type: application/json

{
  "lifespan": "30d"
}
```

### Revoking tokens

To log out or invalidate sessions and revoke the current user's token:

```
POST /api/auth/disavow
```

### Disabling authentication

For development only, authentication can be disabled.

> **Warning:** Auth cannot be disabled in production environments. The system enforces this automatically.

```javascript
export default {
  'adapt-authoring-auth': {
    isEnabled: false
  }
}
```

### Authentication errors

| Error | Description |
| ----- | ----------- |
| `UNAUTHENTICATED` | No valid authentication provided |
| `AUTH_TOKEN_EXPIRED` | Token has expired |
| `AUTH_TOKEN_INVALID` | Token is malformed or tampered |
| `ACCOUNT_DISABLED` | User account is disabled |
| `INVALID_LOGIN_DETAILS` | Wrong username or password |

> **Note:** Auth plugins may define additional errors. For example, the local auth plugin adds `ACCOUNT_LOCKED_TEMP` (too many failed attempts) and `ACCOUNT_LOCKED_PERM` (permanently locked).

## Authorisation

Authorisation determines what authenticated users are allowed to do. The system uses roles to group permissions together.

### Roles

Roles are collections of scopes (permissions) assigned to users. The system comes with three default roles:

**authuser** — Basic authenticated user:
- `clear:session`
- `read:config`
- `read:lang`
- `read:me`
- `write:me`
- `disavow:auth`
  
**contentcreator** _extends authuser_ — Can create and manage content:
- `preview:adapt`
- `publish:adapt`
- `read:assets`
- `write:assets`
- `read:content`
- `write:content`
- `read:contentplugins`
- `read:roles`
- `read:schema`
- `read:tags`
- `write:tags`
- `read:users`
  
**superuser** — Full access to everything:
- `*:*`
  
### Role inheritance

Roles can extend other roles using the `extends` property. The child role inherits all scopes from its parent.

```json
{
  "shortName": "contentcreator",
  "extends": "authuser",
  "scopes": ["read:content", "write:content"]
}
```

In this example, `contentcreator` has all scopes from `authuser` plus `read:content` and `write:content`.

### Defining custom roles

Add roles via configuration in your config file:

```javascript
export default {
  'adapt-authoring-roles': {
    roleDefinitions: [
      {
        shortName: 'reviewer',
        displayName: 'Content Reviewer',
        extends: 'authuser',
        scopes: [
          'read:content',
          'read:assets',
          'preview:adapt'
        ]
      }
    ]
  }
}
```

### Default roles for new users

Configure which roles are assigned to new users:

```javascript
export default {
  'adapt-authoring-roles': {
    defaultRoles: ['authuser'],
    defaultRolesForAuthTypes: {
      local: ['contentcreator']
    }
  }
}
```

### Authorisation errors

| Error | Description |
| ----- | ----------- |
| `UNAUTHORISED` | User lacks required permissions |

## Permissions

Once a user has been authorised and authenticated, the final permissions checks are performed. These are to ensure that the user has access to the specific resources they are requesting.
Permissions control access to specific actions and resources. They are enforced in two ways:
- Using scopes on routes
- Specific manual checks on individual resource items

### Scopes

Scopes are strings in the format `action:resource` that define what a user can do in a plain human-readable way. You will find the most common actions are `read` and `write`, but there are various cases where a more specific and descriptive action is called for.

Some examples are: `read:content`, `delete:assets` and `preview:adapt`.

### Securing routes

**Using routes.json (recommended):**

The preferred way to define routes and their permissions is declaratively in a `routes.json` file in the module root. Permissions are set per HTTP method — use an array of scope strings to secure, or `null` to leave unsecured.

```json
{
  "root": "mymodule",
  "routes": [
    {
      "route": "/action",
      "handlers": { "post": "actionHandler" },
      "permissions": { "post": ["write:myresource"] }
    },
    {
      "route": "/public",
      "handlers": { "get": "publicHandler" },
      "permissions": { "get": null }
    }
  ]
}
```

Then load and register the routes in your module:

```javascript
import { loadRouteConfig, registerRoutes } from 'adapt-authoring-server'

async init () {
  const [auth, server] = await this.app.waitForModule('auth', 'server')
  const config = await loadRouteConfig(this.rootDir, this)
  const router = server.api.createChildRouter(config.root)
  registerRoutes(router, config.routes, auth)
}
```

**Using AbstractApiModule:**

When extending `AbstractApiModule`, define permissions in your route configuration:

```javascript
async setValues () {
  this.root = 'myresource'
  this.schemaName = 'myresource'
  this.collectionName = 'myresources'

  this.routes = [
    {
      route: '/',
      handlers: {
        get: this.getHandler.bind(this),
        post: this.postHandler.bind(this)
      },
      permissions: {
        get: ['read:myresource'],
        post: ['write:myresource']
      }
    }
  ]
}
```

**Using secureRoute directly:**

For cases where imperative route registration is necessary (e.g., dynamic handlers):

```javascript
async init () {
  const auth = await this.app.waitForModule('auth')

  auth.secureRoute('/api/custom/action', 'post', ['custom:action'])
}
```

**Unsecuring routes:**

Some routes need to be publicly accessible (e.g., login endpoints):

> **Warning:** Unsecured routes are accessible without authentication. Use sparingly.

In `routes.json`, set the permission value to `null`:

```json
{
  "permissions": { "get": null }
}
```

Or imperatively:

```javascript
async init () {
  const auth = await this.app.waitForModule('auth')

  auth.unsecureRoute('/api/public/data', 'get')
}
```

### Access control hooks

Although a user may have access to a resource, there may be occasions when more fine-grained control is necessary to filter out specific resources. In this case, you can use hooks to implement custom access control logic.

The `AbstractApiModule#accessCheckHook` is called for each document returned by queries, allowing fine-grained access control:

```javascript
async init () {
  await super.init()
  const content = await this.app.waitForModule('content')
  
  // Check if user owns the document
  content.accessCheckHook.tap((req, doc) => {
    if (doc.createdBy.toString() !== req.auth.user._id.toString()) {
      throw this.app.errors.UNAUTHORISED
    }
  })
}
```

## Further reading

- [Creating auth plugins](creating-auth-plugins.md) — How to implement custom authentication methods
