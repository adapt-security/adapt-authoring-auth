# adapt-authoring-auth

This module provides authentication for the adapt authoring tool.

It uses [Passport local](http://www.passportjs.org/packages/passport-local/) to authenticate with a username and password. 

Upon successful authentication, a [JSON Web Token](https://jwt.io/introduction/) (JWT) is returned. This token must be included in requests to secure routes.

By default all routes are secure.

### Instructions for use

When this module is in use, all routes are secure by default, which means you must be authenticated to use them.

In order to be authenticated, you must pass valid credentials to the auth route. You will need to manually create the first user in the database to do this.

In you adapt-authoring-prototype database, create a 'users' collection and add a record with the following fields:

```
{
    “email”: “email”,
    “password”: “$2a$10$JGnxpVucM0PIJe9f01.GVe8b2ePo/agU6b7RAUpMOxzxLb.c8GkPm”
}
```

This will create a user with password "password".

In Postman (or similar) run:

POST http://localhost:5000/api/users with a request body of:

```
{
    “email”: “email”,
    “password”: “password”
}
```

This will return a JWT. The token will be valid for 24 hours.

Now to use other (secure) routes, you must provide the token in the request header as "x-access-token".

In order to designate a route as unsecure (it will not require any authentication) then you can do:

```
app.auth.unsecureRoute('auth', 'POST');
```