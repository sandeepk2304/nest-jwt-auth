# NestJS JWT authentication example

A small NestJS app that shows JWT login and role-based route protection with `@nestjs/jwt`. It is a learning example: users live in memory and passwords are compared in plain text, so treat it as a reference, not a starter for production.

## What it shows

- `POST /auth/login` checks a username and password and returns an `access_token` signed with `@nestjs/jwt`.
- `AuthGuard` reads the `Authorization: Bearer <token>` header, verifies the token and puts its payload on `request.user`.
- A `@Roles()` decorator stores the roles a route needs as metadata; the guard reads it with `Reflector`.
- `GET /auth/profile` is the protected route that returns the token payload.

```
src/
├── auth/
│   ├── auth.controller.ts      # /auth/login, /auth/profile
│   ├── auth.guard.ts           # Bearer token check + roles metadata
│   ├── auth.service.ts         # signIn, signs the JWT
│   ├── permission.decorators.ts# @Roles()
│   └── constants.ts            # JWT secret (replace before any real use)
└── users/users.service.ts      # two in-memory users
```

## Run it

```bash
npm install
npm run start:dev
```

```bash
# Log in as the demo admin
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"john","password":"changeme"}'

# Call the protected route with the token
curl http://localhost:3000/auth/profile -H "Authorization: Bearer <access_token>"
```

## Before using this for real

- Hash passwords (bcrypt or argon2) and load users from a database.
- Move the JWT secret to an environment variable.
- Check the role on the token payload against the route's roles; the guard here only checks the route metadata.

## Further reading

Longer write-ups on the same ground, from [hisandeep.com](https://www.hisandeep.com):

- [NestJS modules and DI without the ceremony](https://www.hisandeep.com/blog/nestjs-modules-providers-di)
- [NestJS or Express for a new Node API](https://www.hisandeep.com/blog/nestjs-or-express-new-api)
- [Laravel or NestJS for a new backend](https://www.hisandeep.com/blog/laravel-or-nestjs-new-backend)
