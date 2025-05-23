import { DataFunctionArgs, redirect, SessionStorage, Session } from "@remix-run/server-runtime";
import { isResponse } from "@remix-run/server-runtime/dist/responses";
import { json } from "@remix-run/node";
import { Provider, User, AuthConfig, AuthRouteArgs } from "./types";

export { User, Provider, AuthConfig, AuthRouteArgs };

export interface AuthenticatedCallback {
  (user: User): Promise<Response> | Response | Promise<any> | any
}

export class Auth {
  private sessionStorage: SessionStorage;
  private providers: { [key: string]: Provider };
  private defaultRedirectUrl: string;

  constructor(config: AuthConfig) {
    this.sessionStorage = config.sessionStorage;
    this.providers = Object.fromEntries(config.providers.map((provider) => [provider.name, provider]));
    this.defaultRedirectUrl = config.defaultRedirectUrl || "/";
  }

  async loader(args: DataFunctionArgs) {
    const {provider, routeArgs} = this.getProviderAndRouteArgs(args);
    if (routeArgs.route === "logout") {
      return this.logoutLoader(args);
    }
    return provider.loader(routeArgs);
  }

  async action(args: DataFunctionArgs) {
    const {provider, routeArgs} = this.getProviderAndRouteArgs(args);
    return provider.action(routeArgs);
  }

  async authenticated(request: Request, cb: AuthenticatedCallback) {
    return await this.maybeAuthenticated(request, async (user) => {
      if (!user) {
        throw redirect(this.defaultRedirectUrl);
      }
      return cb(user);
    })
  }

  async maybeAuthenticated(request: Request, cb: AuthenticatedCallback) {
    const session = await this.sessionStorage.getSession(request.headers.get("Cookie"));
    const providerName = session.get("provider");
    const sessionUser = session.get("user") || null;
    let updatedUser, provider;
    if (providerName) {
      provider = this.providers[providerName];
      if (provider && sessionUser) {
        await provider.authenticate(sessionUser, async (user) => {
          updatedUser = user;
        });
      }
    }
    const user = updatedUser === undefined ? sessionUser : updatedUser;
    let result, shouldThrow = false;
    try {
      result = await cb(user);
    } catch (error) {
      if (!isResponse(error)) {
        throw error;
      }
      result = error;
      shouldThrow = true;
    }
    let response: Response;
    if (result instanceof Promise) {
      result = await result;
    }
    if (isResponse(result)) {
      response = result;
    } else {
      response = json(result);
    }
    let shouldCommitSession = false;
    if (providerName && (!provider || !user)) {
      // The user has been logged out or the session is otherwise invalid so
      // clear it.
      session.unset("provider");
      session.unset("user");
      shouldCommitSession = true;
    } else if (updatedUser) {
      session.set("user", updatedUser);
      shouldCommitSession = true;
    }
    if (shouldCommitSession) {
      response.headers.append("Set-Cookie", await this.sessionStorage.commitSession(session));
    }
    if (shouldThrow) {
      throw response;
    }
    return response;
  }

  private async logoutLoader({ request }: DataFunctionArgs) {
    const session = await this.sessionStorage.getSession(request.headers.get("Cookie"));
    session.unset("provider");
    session.unset("user");
    const params = new URL(request.url).searchParams;
    const redirectUrl = params.get("redirectUrl") || this.defaultRedirectUrl;
    throw redirect(redirectUrl, {
      headers: { "Set-Cookie": await this.sessionStorage.commitSession(session) },
    });
  }

  private getProviderAndRouteArgs(args: DataFunctionArgs) {
    const { request } = args;
    const url = new URL(request.url)
    const parts = url.pathname.split("/");
    const [route, providerName] = parts.reverse();
    if (!providerName || !route) {
      throw new Response("Not Found", { status: 404 });
    }
    const provider = this.providers[providerName];
    if (!provider) {
      throw new Response("Not Found", { status: 404 });
    }
    const commitSession = async (user: User) => {
      const session = await this.sessionStorage.getSession(request.headers.get("Cookie"));
      session.set("provider", providerName);
      session.set("user", user);
      return await this.sessionStorage.commitSession(session);
    }
    return { provider, routeArgs: { ...args, route, commitSession } };
  }
}