# adapt-authoring-auth

Authentication and authorisation for the Adapt authoring tool. Defines the `AbstractAuthModule` base class that concrete auth strategies (e.g. [adapt-authoring-auth-local](../adapt-authoring-auth-local)) extend, and enforces scope-based access control across the API.

Extends `AbstractModule` from [adapt-authoring-core](../adapt-authoring-core).

## Documentation

- [Access control](docs/access-control.md) — how requests are authorised
- [Auth permissions](docs/auth-permissions.md) — scopes and what they grant
- [Creating auth plugins](docs/creating-auth-plugins.md) — implementing a new auth strategy
