# Access control

This guide covers **authorisation** — what an authenticated user is allowed to do, and which individual records they may see. Authentication (proving identity, tokens, sessions) is covered separately in [Authentication and permissions](auth-permissions.md).

Authorisation happens at three levels:

1. **Scopes** — named permissions a user carries, e.g. `read:content`.
2. **Roles** — bundles of scopes assigned to users (`adapt-authoring-roles`).
3. **Per-record access** — hooks that filter or deny individual documents at query time (`adapt-authoring-api`).

## Scopes

A scope is a string in the form `action:resource`, e.g. `read:content`, `write:users`, `preview:adapt`. The common actions are `read` and `write`, but more descriptive actions are used where they communicate intent better (`publish:adapt`, `assign:roles`, `generatetoken:auth`, `import:adapt`).

A user's scopes are the union of the scopes of every role assigned to them (including inherited roles). They are attached to each request as `req.auth.scopes` (an array of strings).

### The superuser wildcard

`*:*` is a wildcard that grants everything. It is not pattern-matched — the system treats it as the `isSuper` flag (`req.auth.isSuper`). Super users **bypass** route permission checks and the `accessQueryHook`/`accessCheckHook` access filtering described below. Reserve `*:*` for the superuser role only.

## Roles

Roles are documents in the `roles` collection, managed by `adapt-authoring-roles` (which extends `AbstractApiModule`). Each role has:

- `shortName` — unique id used in config and `extends` (e.g. `contentcreator`)
- `displayName` — human-readable label
- `extends` — optional `shortName` of a parent role to inherit scopes from
- `scopes` — array of scope strings this role grants

### Inheritance

A role inherits all scopes of the role named in `extends`, recursively. `getScopesForRole` walks the `extends` chain and concatenates scopes, so a deep chain (`admin` → `contentcreator` → `reviewer` → `authuser`) accumulates every ancestor's scopes.

### Defining roles via config

Roles are declared under `adapt-authoring-roles.roleDefinitions` in a config file. On startup `initConfigRoles` upserts each definition into the `roles` collection (insert if new, replace if the `shortName` already exists) — so config is the source of truth and edits to it take effect on restart.

The real default role set (from `conf/defaults.config.js`) shows the inheritance chain in practice:

```javascript
export default {
  'adapt-authoring-roles': {
    roleDefinitions: [
      {
        shortName: 'authuser',
        displayName: 'Authenticated user',
        scopes: [
          'read:config', 'read:lang',
          'read:me', 'write:me'
        ]
      },
      {
        shortName: 'reviewer',
        displayName: 'Reviewer',
        extends: 'authuser',
        scopes: [
          'preview:adapt', 'read:assets', 'read:content', 'write:content',
          'read:comments', 'write:comments', 'read:contentplugins',
          'read:roles', 'read:schema', 'read:tags', 'read:users',
          'read:usergroups'
        ]
      },
      {
        shortName: 'contentcreator',
        displayName: 'Content creator',
        extends: 'reviewer',
        scopes: [
          'publish:adapt', 'write:assets', 'write:content',
          'write:tags', 'read:adaptcollab'
        ]
      },
      {
        shortName: 'admin',
        displayName: 'Administrator',
        extends: 'contentcreator',
        scopes: [
          'import:adapt', 'export:adapt', 'update:adapt',
          'generatetoken:auth', 'debug', 'install:contentplugins',
          'update:contentplugins', 'write:contentplugins', 'read:docs',
          'read:logs', 'assign:roles', 'register:users', 'write:users',
          'write:usergroups'
        ]
      },
      {
        shortName: 'superuser',
        displayName: 'Super user',
        scopes: ['*:*']
      }
    ]
  }
}
```

`admin` here resolves to its own scopes plus all of `contentcreator`, `reviewer` and `authuser`. To add a custom role, append another entry — extend an existing role and add only the extra scopes.

### Default roles for new users

Which roles a newly created user receives is also config-driven:

```javascript
export default {
  'adapt-authoring-roles': {
    defaultRoles: ['authuser'],                  // applied to everyone
    defaultRolesForAuthTypes: {
      local: ['contentcreator']                  // applied per auth type
    }
  }
}
```

`initDefaultRoles` taps the users `preInsertHook`: if an incoming user has no `roles`, it assigns the auth-type-specific roles (keyed on `authType`), falling back to `defaultRoles`.

### Protecting role changes

`adapt-authoring-roles` guards privilege escalation via the users `requestHook` (`onUpdateRoles`) and `accessCheckHook` (`onCheckUserAccess`). Non-super users need `assign:roles` to change anyone's roles, cannot grant the superuser role, and cannot modify a superuser. These checks are skipped for super users.

## Gating routes by scope

Route permissions are enforced by the `Permissions` class in `adapt-authoring-auth`. Key rules:

- **Every route is denied by default.** A route with no permissions entry is blocked, and a warning is logged.
- A request passes only if `req.auth.scopes` contains **every** scope the route requires (`neededScopes.every(s => userScopes.includes(s))`).
- Super users (`req.auth.isSuper`) bypass the check entirely.
- `HEAD` reuses `GET`'s required scopes (Express routes `HEAD` through the `GET` handler).

The recommended way to declare route scopes is a `routes.json` file, or the `routes` array on an `AbstractApiModule` — see [Authentication and permissions › Securing routes](auth-permissions.md#securing-routes) for the full mechanics (`routes.json`, `AbstractApiModule`, `secureRoute`/`unsecureRoute`, and unsecured routes). This guide does not repeat those.

Scope checks answer *"may this user call this endpoint at all?"* They cannot express *"which records may this user see?"* — that is what the access hooks below are for.

## Scoped tokens

`req.auth.scopes` is normally the union of the user's role scopes (above). A token may instead be **scoped** — restricted at mint time to a subset of those scopes — in which case the request carries only that subset:

- `AuthToken.generate(authType, user, { scopes })` persists the given `scopes` on the token, validated as a subset of the user's own (a super user, holding all scopes, may request any concrete set). `initRequestData` then narrows `req.auth.scopes` to that set and recomputes `isSuper` on it — so a scoped token is never a super token.
- Omitting `scopes` yields an ordinary token that inherits the user's full role scopes at verification time (this is what login tokens do).

Scoped tokens let a trusted server-side caller mint a narrow credential for a user — e.g. a token limited to `read:content`/`write:content` for an external service — without handing over the user's full authority.

**Super users cannot create elevated tokens.** A super user (`*:*`) may not mint a full-scope bearer token: `POST /auth/generatetoken` is refused for them, and `AuthToken.generate` rejects a `manual` token for a super user, or any `scopes` containing the `*:*` wildcard. A super user may still be issued a *scoped* (non-super) token, and their interactive login session is unaffected.

## Per-record access: the access hooks

Scopes are coarse: `read:content` lets a user hit `GET /api/content`, but a user should usually only see *their own* (or shared) courses, not everyone's. `AbstractApiModule` exposes two hooks for this fine-grained filtering. Both are skipped for super users.

### `accessQueryHook` (preferred)

Invoked **before** a query runs. Observers merge access-control clauses into `req.apiData.query`, so the database only ever returns records the user may see.

```javascript
// AbstractApiModule.requestHandler
await this.requestHook.invoke(req)
if (!req.auth.isSuper) await this.accessQueryHook.invoke(req)
```

Because the filtering happens in the query, pagination counts and the `Link` header stay accurate, and there is no need to top up short pages.

**Real example — `adapt-authoring-usergroups`** restricts shareable content (courses, assets) to documents the user shares a group with:

```javascript
mod.accessQueryHook.tap(req => {
  const query = req.apiData.query
  query.$and = [...(query.$and ?? []), buildGroupAccessQuery(req.auth?.user?.userGroups)]
})
```

It deliberately uses `accessQueryHook` rather than `accessCheckHook` (see the inline rationale in `UserGroupsModule.registerModule`): query-level filtering avoids short pages and wrong counts.

### `accessCheckHook` (safety net)

Invoked **after** the query, once per returned document, via `checkAccess`:

```javascript
// checkAccess — runs per record for non-super users
if (!this.accessCheckHook.hasObservers ||
    (await this.accessCheckHook.invoke(req, r)).every(Boolean)) {
  filtered.push(r)
}
```

Observer return semantics:

- `return true` — allow
- `return false` / `undefined` / any non-truthy — deny
- `throw` — deny; for single-document requests the thrown error propagates

A **single-document** request denied by any observer responds `401 Unauthorised`. A **list** request silently filters out the denied items — which is exactly why it produces short pages and breaks skip-based pagination for callers that infer end-of-results from response length.

```javascript
// deny documents the requesting user doesn't own
content.accessCheckHook.tap((req, doc) => {
  if (doc.createdBy.toString() !== req.auth.user._id.toString()) {
    throw this.app.errors.UNAUTHORISED
  }
})
```

### Which hook to use

| | `accessQueryHook` | `accessCheckHook` |
| --- | --- | --- |
| When it runs | before the query | per document, after the query |
| Effect on lists | accurate counts & pagination | short pages, broken skip-pagination |
| Runs for super users | no | no |
| Best for | all access filtering | checks that genuinely cannot be expressed as a query |

**Rule: prefer `accessQueryHook`.** Only fall back to `accessCheckHook` when the access rule cannot be expressed as a query, or as a defence-in-depth safety net. The content module uses `accessCheckHook` this way in its custom `tree` handler — the handler bypasses the standard per-item check, so it re-applies it by hand and returns `404` (not `403`) so it doesn't leak the course's existence.

### Don't confuse these with `queryHook`

`AbstractApiModule` also has a `queryHook`. Unlike the access hooks it runs for **every** user, including super users, and expresses *what the user asked to see* (e.g. a dashboard filter) rather than *what they are permitted to see*. Use `accessQueryHook` for authorisation; use `queryHook` for user-driven filters.

## Further reading

- [Authentication and permissions](auth-permissions.md) — tokens, sessions, `req.auth`, securing routes
- [Creating auth plugins](creating-auth-plugins.md) — implementing custom authentication methods
