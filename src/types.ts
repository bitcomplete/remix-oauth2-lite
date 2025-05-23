import { SessionStorage } from "@remix-run/server-runtime";

export interface AppState {
  airtable?: {
    baseId?: string;
    tableId?: string;
  };
  google?: {
    workspace?: string;
  };
  github?: {
    organization?: string;
  };
}

export interface User {
  accessToken: string;
  email: string;
  providerState: {
    expiresAt: number;
    token: Token;
    userInfo: UserInfo;
  };
  appState: AppState;
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

export interface ProviderState {
  expiresAt: number;
  token: Token;
  userInfo: UserInfo;
}

export interface UserValidator {
  (user: User): Promise<boolean>;
}

export interface AuthConfig {
  sessionStorage: SessionStorage;
  providers: Provider[];
  defaultRedirectUrl?: string;
}

export interface Provider {
  name: string;
  loader: (args: AuthRouteArgs) => Promise<Response>;
  action: (args: AuthRouteArgs) => Promise<Response>;
  authenticate: (user: User, setUser: (user: User | null) => void) => Promise<void>;
}

export interface AuthRouteArgs {
  request: Request;
  params: Record<string, string | undefined>;
  route: string;
  commitSession: (user: User) => Promise<string>;
} 