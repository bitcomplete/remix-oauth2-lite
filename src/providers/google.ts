import { Provider } from ".";
import OAuth2Provider, { Token, UserInfo, UserValidator } from "./oauth2";

// TODO: This should use the OpenID Connect protocol [1] including fetching the
// discovery document, but we instead use older OAuth2 endpoints. They are
// unlikely to be removed but are technical deprecated.
// [1]: https://developers.google.com/identity/protocols/oauth2/openid-connect

interface GoogleOptions {
  name?: string;
  clientId: string;
  clientSecret: string;
  scope: string;
  redirectUriBase?: string;
  userValidator?: UserValidator;
}

class GoogleProvider extends OAuth2Provider implements Provider {
  constructor(options: GoogleOptions) {
    super({
      ...options,
      name: options.name || "google",
      authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth?prompt=consent&access_type=offline",
      tokenUrl: "https://oauth2.googleapis.com/token",
      userValidator: options.userValidator,
    });
  }

  protected async fetchToken(params: {[key: string]: string}): Promise<Token> {
    const token = await super.fetchToken(params);
    // Strip out the id_token field since it's a big JWT that we don't need and
    // would otherwise bloat the session.
    delete token["id_token"];
    return token;
  }

  protected async fetchUserInfo(token: Token): Promise<UserInfo> {
    let params = new URLSearchParams({access_token: token.access_token});
    const url = `https://www.googleapis.com/oauth2/v2/userinfo?${params}`;
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(await response.text());
    }
    const userInfo = await response.json();
    ['email'].forEach((key) => {
      if (!userInfo[key]) {
        throw new Error(`Google userinfo missing ${key}`);
      }
    });
    return { email: userInfo.email };
  }
}

export default GoogleProvider;