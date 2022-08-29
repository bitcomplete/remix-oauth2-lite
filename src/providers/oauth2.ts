import { redirect } from "@remix-run/server-runtime";
import { randomBytes } from "crypto";
import { AuthRouteArgs, Provider } from ".";
import { Params } from "react-router";

interface OAuth2Options {
  name?: string;
  authorizationUrl: string;
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  scope?: string;
}

class OAuth2Provider implements Provider {
  name: string;
  authorizationUrl: string;
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  scope?: string;

  constructor(options: OAuth2Options) {
    this.name = options.name || "oauth2";
    this.authorizationUrl = options.authorizationUrl;
    this.tokenUrl = options.tokenUrl;
    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret;
    this.scope = options.scope;
  }

  async loader(args: AuthRouteArgs) {
    const { route } = args;
    switch (route) {
      case "callback":
        return await this.callbackLoader(args);
      case "login":
        return await this.loginLoader(args);
      default:
        throw new Response("Not Found", { status: 404 });
    }
  }

  async action(args: AuthRouteArgs) {
    throw new Response("Not Found", { status: 404 });
  }

  private async callbackLoader({ sessionStorage, request, params }: AuthRouteArgs) {
    const queryParams = new URL(request.url).searchParams;
    let stateUrl = queryParams.get("state");
    if (!stateUrl) {
      throw new Response("Missing state on URL", { status: 400 });
    }
    let session = await sessionStorage.getSession(request.headers.get("Cookie"));
    let stateSession = session.get("state");
    if (!stateSession) {
      throw new Response("Missing state on session", { status: 400 });
    }
    if (stateSession !== stateUrl) {
      throw new Response("State doesn't match", { status: 400 });
    }
    session.unset("state");
    let code = queryParams.get("code");
    if (!code) {
      throw new Response("Missing code", { status: 400 });
    }

    let tokenParams = new URLSearchParams();
    tokenParams.set("grant_type", "authorization_code");
    tokenParams.set("redirect_uri", this.getCallbackUrl(request, params).toString());
    tokenParams.set("client_id", this.clientId);
    tokenParams.set("client_secret", this.clientSecret);
    tokenParams.set("code", code);

    const response = await fetch(this.tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: tokenParams,
    });

    if (!response.ok) {
      try {
        const body = await response.text();
        throw new Response(body, { status: 401 });
      } catch (error) {
        throw new Response((error as Error).message, { status: 401 });
      }
    }

    const {
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: expiresIn,
      email,
    } = await response.json();
    session.set("user", {
      accessToken,
      refreshToken,
      email,
    });

    return redirect(queryParams.get("redirectUrl") || "/", {
      headers: {
        "Set-Cookie": await sessionStorage.commitSession(session, {
          // TODO: Refresh the access token using the refresh token if it expires.
          // For now we simply expire the session.
          expires: new Date(Date.now() + expiresIn * 1000),
        }),
      },
    });
  }

  private async loginLoader({ sessionStorage, request, params }: AuthRouteArgs) {
    const session = await sessionStorage.getSession(
      request.headers.get("Cookie")
    );
    const state = randomBytes(16).toString("hex");
    session.set("state", state);

    let authParams = new URLSearchParams();
    authParams.set("response_type", "code");
    authParams.set("client_id", this.clientId);
    authParams.set("redirect_uri", this.getCallbackUrl(request, params).toString());
    authParams.set("state", state);
    if (this.scope) {
      authParams.set("scope", this.scope);
    }
    const authUrl = new URL(this.authorizationUrl);
    authUrl.search = authParams.toString();

    throw redirect(authUrl.toString(), {
      headers: { "Set-Cookie": await sessionStorage.commitSession(session) },
    });
  }

  private getCallbackUrl(request: Request, params: Params<string>) {
    const url = new URL(request.url);
    const pathSuffix = params["*"] || "";
    const pathPrefix = url.pathname.substring(
      0,
      url.pathname.length - pathSuffix.length
    );
    const callbackUrl = new URL(`${pathPrefix}/${this.name}/callback`, url);
    const redirectUrl = url.searchParams.get("redirectUrl");
    if (redirectUrl) {
      callbackUrl.searchParams.set("redirectUrl", redirectUrl);
    }
    return callbackUrl;
  }
}

export default OAuth2Provider;
