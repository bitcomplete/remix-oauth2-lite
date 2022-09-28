import { Cookie, redirect } from "@remix-run/server-runtime";
import { createCookie } from "@remix-run/node";
import { randomBytes } from "crypto";
import { AuthRouteArgs, Provider, User } from ".";
import { Params } from "react-router";

interface OAuth2Options {
  name?: string;
  authorizationUrl: string;
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  scope?: string;
}

export interface Token {
  access_token: string;
  refresh_token?: string;
  expires_in: number;
  email: string;
  [key: string]: unknown;
}

export interface UserInfo {
  email: string;
  [key: string]: unknown;
}

interface ProviderState {
  expiresAt: number;
  token: Token;
  userInfo: UserInfo;
}

class OAuth2Provider implements Provider {
  name: string;
  authorizationUrl: string;
  tokenUrl: string;
  clientId: string;
  clientSecret: string;
  scope?: string;
  stateCookie: Cookie;

  constructor(options: OAuth2Options) {
    this.name = options.name || "oauth2";
    this.authorizationUrl = options.authorizationUrl;
    this.tokenUrl = options.tokenUrl;
    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret;
    this.scope = options.scope;
    this.stateCookie = createCookie(`remix-oauth2-lite-${this.name}-state`, {
      httpOnly: true,
      maxAge: 60 * 5,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
    });
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

  async authenticate(user: User, setUser: (user: User | null) => void) {
    const state = user.providerState as ProviderState;
    // If the token is within 5 minutes of expiry then preemptively refresh it.
    // This should reduce the chances of it expiring during request processing.
    if (new Date() < new Date(state.expiresAt - 5 * 60 * 1000)) {
      return;
    }
    const {refresh_token: refreshToken} = state.token;
    if (!refreshToken) {
      setUser(null);
      return;
    }
    let token;
    try {
      token = await this.fetchToken({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      })
    } catch (error) {
      console.error(error);
      setUser(null);
      return;
    }
    const userInfo = (user.providerState as ProviderState).userInfo;
    setUser({
      accessToken: token.access_token,
      email: userInfo.email,
      providerState: {
        expiresAt: Date.now() + token.expires_in * 1000,
        token,
        userInfo,
      }
    });
  }

  private async callbackLoader({ request, params, commitSession }: AuthRouteArgs) {
    const queryParams = new URL(request.url).searchParams;
    const redirectUrl = queryParams.get("redirectUrl") || "/";
    let stateUrl = queryParams.get("state");
    if (!stateUrl) {
      return redirect(redirectUrl + "?error=missing_state_parameter");
    }
    const stateCookieValue = await this.stateCookie.parse(request.headers.get("Cookie"));
    if (!stateCookieValue) {
      return redirect(redirectUrl + "?error=missing_state_cookie");
    }
    if (stateCookieValue !== stateUrl) {
      return redirect(redirectUrl + "?error=state_mismatch");
    }
    let code = queryParams.get("code");
    if (!code) {
      return redirect(redirectUrl + "?error=missing_code_parameter");
    }

    let token;
    try {
      token = await this.fetchToken({
        grant_type: "authorization_code",
        redirect_uri: this.getCallbackUrl(request, params).toString(),
        code,
      });
    } catch (error) {
      console.error(error);
      return redirect(redirectUrl + "?error=token_request_failed");
    }

    let userInfo;
    try {
      userInfo = await this.fetchUserInfo(token);
    } catch (error) {
      console.error(error);
      return redirect(redirectUrl + "?error=user_info_request_failed");
    }
    const user = {
      accessToken: token.access_token,
      email: userInfo.email,
      providerState: {
        expiresAt: Date.now() + token.expires_in * 1000,
        token,
        userInfo,
      }
    };
    return redirect(redirectUrl, {
      headers: {"Set-Cookie": await commitSession(user)},
    });
  }

  private async loginLoader({ request, params }: AuthRouteArgs) {
    const state = randomBytes(16).toString("hex");

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
      headers: {"Set-Cookie": await this.stateCookie.serialize(state)},
    });
  }

  private getCallbackUrl(request: Request, params: Params<string>) {
    const url = new URL(request.url);
    const pathSuffix = params["*"] || "";
    const pathPrefix = url.pathname.substring(
      0,
      url.pathname.length - pathSuffix.length
    );
    const callbackUrl = new URL(`${pathPrefix}${this.name}/callback`, url);
    const redirectUrl = url.searchParams.get("redirectUrl");
    if (redirectUrl) {
      callbackUrl.searchParams.set("redirectUrl", redirectUrl);
    }
    return callbackUrl;
  }

  protected async fetchToken(params: {[key: string]: string}): Promise<Token> {
    let tokenParams = new URLSearchParams();
    tokenParams.set("client_id", this.clientId);
    tokenParams.set("client_secret", this.clientSecret);
    Object.entries(params).forEach(([key, value]) => {
      tokenParams.set(key, value);
    })
    const response = await fetch(this.tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: tokenParams,
    });
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const token = await response.json();
    ['access_token', 'expires_in'].forEach((key) => {
      if (!token[key]) {
        throw new Error(`OAuth token missing ${key}`);
      }
    })
    return token;
  }

  protected async fetchUserInfo(token: Token): Promise<UserInfo> {
    const { email } = token;
    if (!email) {
      throw new Error("OAuth2 token missing email");
    }
    return { email };
  }
}

export default OAuth2Provider;
