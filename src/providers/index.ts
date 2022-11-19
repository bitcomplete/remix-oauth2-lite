import { DataFunctionArgs } from "@remix-run/server-runtime";

export type User = {
  email: string;
  accessToken: string;
  providerState: any;
  appState: any;
};

export interface AuthRouteArgs extends DataFunctionArgs {
  route: string;
  commitSession: (user: User) => Promise<string>;
}

export interface Provider {
  name: string;
  loader(args: AuthRouteArgs): Promise<any>;
  action(args: AuthRouteArgs): Promise<any>;
  authenticate(user: User, setUser: (user: User | null) => void): Promise<void>;
}