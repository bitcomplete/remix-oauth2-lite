import { DataFunctionArgs, redirect, SessionStorage } from "@remix-run/server-runtime";
import { Provider } from "./providers";

export type User = {
  accessToken: string;
  refreshToken: string;
  email: string;
};

export class Auth {
  sessionStorage: SessionStorage;
  providers: { [key: string]: Provider };

  constructor(sessionStorage: SessionStorage, providers: Provider[]) {
    this.sessionStorage = sessionStorage;
    this.providers = Object.fromEntries(providers.map((provider) => [provider.name, provider]));
  }

  async loader(args: DataFunctionArgs) {
    const {provider, route} = this.getProviderAndRoute(args.request);
    if (route === "logout") {
      return this.logoutLoader(args);
    }
    return provider.loader({ ...args, route, sessionStorage: this.sessionStorage });
  }

  async action(args: DataFunctionArgs) {
    const {provider, route} = this.getProviderAndRoute(args.request);
    return provider.action({ ...args, route, sessionStorage: this.sessionStorage });
  }

  async assertIsLoggedIn(request: Request) {
    const session = await this.sessionStorage.getSession(request.headers.get("Cookie"));
    const user = session.get("user") as User;
    if (!user) {
      throw redirect("/");
    }
    return user;
  }

  async isLoggedIn(request: Request) {
    const session = await this.sessionStorage.getSession(request.headers.get("Cookie"));
    return !!session.get("user");
  }

  private async logoutLoader({ request }: DataFunctionArgs) {
    let session = await this.sessionStorage.getSession(request.headers.get("Cookie"));
    const params = new URL(request.url).searchParams;
    const redirectUrl = params.get("redirectUrl") || "/";
    throw redirect(redirectUrl, {
      headers: { "Set-Cookie": await this.sessionStorage.destroySession(session) },
    });
  }

  private getProviderAndRoute(request: Request) {
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
    return { provider, route };
  }
}