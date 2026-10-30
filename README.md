# auth-basic-improve

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js >= 24](https://img.shields.io/badge/Node.js-%3E=24-brightgreen)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4%2B-blue)](https://www.typescriptlang.org/)

A lightweight, TypeScript-native **Basic Authentication parser** for Node.js & Express.js.

> Supports **static user validation**, **custom synchronouss/async authorizers**, **timing-safe comparisons**, and **configurable challenge headers**.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [1. Parse Basic Auth String](#1-parse-basic-auth-string)
  - [2. Extract Auth from Express Request](#2-extract-auth-from-express-request)
  - [3. Express Middleware](#3-express-middleware)
    - [Static Users](#static-users)
    - [Custom Synchronous Authorizer](#custom-synchronous-authorizer)
    - [Custom Asynchronous Authorizer](#custom-asynchronous-authorizer)
    - [Challenge Mode](#challenge-mode)
    - [Custom Response Body](#custom-response-body)
    - [Safe Compare](#safe-compare)
- [API Reference](#api-reference)
- [Project Structure](#project-structure)
- [Development](#development)
- [License](#license)

---

## Features

- **Core Parser**: Extract `username` and `password` from base64-encoded Basic Auth headers.
- **Express Middleware**: Drop-in authentication middleware for Express.js routes.
- **Timing-Safe Comparison**: Prevents timing attacks via `timingSafeEqual`.
- **Flexible Authorizers**: Use static user lists, sync, or async custom functions.
- **Challenge Mode**: Send `WWW-Authenticate` headers for browser pop-ups.
- **Custom Responses**: Return static strings, JSON, or dynamic messages on 401.
- **Fully Typed**: 100% TypeScript with exported interfaces.

---

## Installation

```bash
# Using Yarn (recommended, packageManager: yarn@4.5.0)
yarn add auth-basic-improve

# Using npm
npm install auth-basic-improve
```

**Requirements**: Node.js `>= 24`

---

## Usage

### 1. Parse Basic Auth String

Extract credentials directly from a base64-encoded string:

```typescript
import { parse } from "auth-basic-improve";

const result = parse("Basic Zm9vOmJhcg==");
// Returns: { name: "foo", pass: "bar" }
// Returns "" for invalid/malformed strings
```

### 2. Extract Auth from Express Request

Parse the `Authorization` header from an Express `Request` object:

```typescript
import { auth } from "auth-basic-improve";

app.get("/protected", (req, res) => {
  const credentials = auth(req);

  if (typeof credentials === "string") {
    return res.status(401).send("Unauthorized");
  }

  console.log(credentials.name); // "foo"
  console.log(credentials.pass); // "bar"
  res.send("Authenticated!");
});
```

### 3. Express Middleware

Build a full authentication middleware with `buildMiddleware` (default export):

```typescript
import basicAuth from "auth-basic-improve/expressBasicAuth";
```

#### Static Users

Define users directly in the options:

```typescript
const authMiddleware = basicAuth({
  challenge: false,
  users: { Admin: "secret1234", User: "password123" },
});

app.get("/admin", authMiddleware, (req, res) => {
  res.send("Welcome, Admin!");
});
```

#### Custom Synchronous Authorizer

Provide your own validation logic:

```typescript
const myAuthorizer = (username: string, password: string): boolean => {
  // e.g., query a database
  return username.startsWith("A") && password.startsWith("secret");
};

const authMiddleware = basicAuth({ authorizer: myAuthorizer });
```

#### Custom Asynchronous Authorizer

For database lookups or async operations:

```typescript
const myAsyncAuthorizer = (
  username: string,
  password: string,
  cb: (err: Error | null, result: boolean) => void
): void => {
  // Simulate async DB query
  db.findUser(username, (err, user) => {
    if (err) return cb(err, false);
    cb(null, user && user.password === password);
  });
};

const authMiddleware = basicAuth({
  authorizeAsync: true,
  authorizer: myAsyncAuthorizer,
});
```

#### Challenge Mode

Send a `WWW-Authenticate` header to trigger browser credential prompts:

```typescript
const authMiddleware = basicAuth({
  challenge: true,
  users: { Admin: "secret1234" },
});
// On 401, response includes: WWW-Authenticate: Basic realm="..."
```

Custom realm:

```typescript
const authMiddleware = basicAuth({
  challenge: true,
  realm: "My Protected Area",
  users: { Admin: "secret1234" },
});
// Response: WWW-Authenticate: Basic realm="My Protected Area"
```

#### Custom Response Body

Control the 401 response content:

```typescript
// Static string
const authMiddleware = basicAuth({
  unauthorizedResponse: "Access Denied",
});

// JSON object
const authMiddleware = basicAuth({
  unauthorizedResponse: { error: "Unauthorized", code: 401 },
});

// Dynamic function
const authMiddleware = basicAuth({
  unauthorizedResponse: (req) =>
    req.auth
      ? `Credentials ${req.auth.user}:${req.auth.password} rejected`
      : "No credentials provided",
  users: { Foo: "bar" },
});
```

#### Safe Compare

Use timing-safe string comparison to prevent timing attacks:

```typescript
import basicAuth from "auth-basic-improve/expressBasicAuth";

const myAuthorizer = (username: string, password: string): boolean => {
  return (
    basicAuth.safeCompare(username, "ExpectedUser") &&
    basicAuth.safeCompare(password, "ExpectedPass")
  );
};
```

---

## API Reference

### `parse(str?: string) => IAuthObject | string`

Parses a base64-encoded Basic Auth string.

| Parameter | Type     | Required | Description           |
| --------- | -------- | -------- | --------------------- |
| `str`     | `string` | No       | Base64-encoded auth string |

**Returns**: `{ name: string, pass: string }` on success, `""` on failure.

---

### `auth(req?: Request) => IAuthObject | string`

Extracts and parses the `Authorization` header from an Express request.

| Parameter | Type      | Required | Description            |
| --------- | --------- | -------- | ---------------------- |
| `req`     | `Request` | Yes      | Express request object |

**Returns**: `{ name: string, pass: string }` on success, `""` on failure.

---

### `buildMiddleware(options: IbuildMiddleware) => (req, res, next) => void`

Creates an Express authentication middleware.

| Option                | Type               | Default          | Description                          |
| --------------------- | ------------------ | ---------------- | ------------------------------------ |
| `challenge`           | `boolean`          | `false`          | Send `WWW-Authenticate` header       |
| `users`               | `Record<string, string>` | `{}`       | Static username → password map       |
| `authorizer`          | `function`         | —                | Custom validation function           |
| `authorizeAsync`      | `boolean`          | `false`          | Enable async authorizer              |
| `unauthorizedResponse`| `unknown`          | `""`             | Custom 401 response body             |
| `realm`               | `string \| function` | `undefined`    | Custom realm string or generator     |

---

### `safeCompare(userInput: string, secret: string) => boolean`

Performs a timing-safe comparison of two strings using `crypto.timingSafeEqual`.

---

## Project Structure

```
src/
├── index.ts                        # Main entry point — re-exports everything
├── app.ts                          # Aggregates core auth module
├── basicAuth/
│   └── index.ts                    # Core parser: parse() & auth()
├── expressBasicAuth/
│   └── index.ts                    # Express middleware builder
├── interfaces/
│   ├── basicAuth.interface.ts      # IAuthObject, IRequestHeaderAuthorization
│   └── expressBasicAuth.interface.ts # IBasicAuthedRequest, IbuildMiddleware
└── utils/
    └── constant.util.ts             # Project constants

tests/
├── unit/
│   └── basicAuth.test.ts           # Unit tests for parse() & auth()
└── integration/
    └── expressBasicAuth.test.ts    # Integration tests for middleware
```

See [README_STRUCTURE.md](./README_STRUCTURE.md) for a detailed file-by-file breakdown.

---

## Development

```bash
# Install dependencies
yarn install

# Build TypeScript → JavaScript
yarn build

# Run tests
yarn test

# Run tests with coverage
yarn test:coverage

# Run unit tests only
yarn test:unit

# Lint & fix
yarn lint

# Bundle size check
yarn size
```

---

## License

[MIT](./LICENSE) © Tri Bui Quang
