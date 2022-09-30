remix-oauth2-lite is an authentication and authorization library for the Remix
web framework. It supports some OAuth2 providers out of the box, and offers a
simple API for authorization in a Remix app.

# Quick start

① Create session storage and an Auth object:

```
import { createCookieSessionStorage } from "remix";
import { Auth } from "remix-oauth2-lite";

// ~/lib/auth.server.tsx
const sessionStorage = createCookieSessionStorage({
  cookie: {
    name: "my-site-session",
    sameSite: "lax",
    path: "/",
    httpOnly: true,
    secrets: [SESSION_SECRET],
    secure: process.env.NODE_ENV === "production",
  },
});

export const auth = new Auth(sessionStorage, [
  // providers here...
  // See the Providers section below for more details.
]);
```

② Create a splat route to handle auth endpoints:

```
// routes/auth/$.tsx
import { LoaderFunction } from "@remix-run/server-runtime";
import { auth } from "~/services/auth.server";

export const loader: LoaderFunction = async (args) => auth.loader(args);

export default function () {
  return null;
}
```

③ Authenticate requests on routes that should be protected:

```
// routes/someroute.tsx
export let loader: LoaderFunction = async ({ request }) => {
  return await auth.authenticated(request, async (user) => {
    // Logged out users will be redirect to "/".
    return json({ user })
  });
};
```

④ Direct users to provider-specific sign-in/sign-out links:

```
// Sign in link for myprovider
<Link to="/auth/someprovider/login">Sign In</Link>

// Sign out link for myprovider
<Link to="/auth/someprovider/logout">Sign Out</Link>
```

# Providers

Most authentication logic is specific to a provider, each of which is described
below.

## Google

```
export const auth = new Auth(sessionStorage, [
  new GoogleProvider({
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    scope: "email"
  }),
]);
```

## Generic OAuth2

export const auth = new Auth(sessionStorage, [
new OAuth2Provider({
authorizationUrl: `https://some-provider.com/oauth2/authorize`,
tokenUrl: `https://some-provider.com/oauth2/token`,
clientId: CLIENT_ID,
clientSecret: CLIENT_SECRET,
}),
]);

```

```
