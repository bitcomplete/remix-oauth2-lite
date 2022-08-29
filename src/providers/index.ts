import { DataFunctionArgs, SessionStorage } from "@remix-run/server-runtime";

export interface AuthRouteArgs extends DataFunctionArgs {
  route: string;
  sessionStorage: SessionStorage;
}

export interface Provider {
  name: string;
  loader(args: AuthRouteArgs): Promise<any>;
  action(args: AuthRouteArgs): Promise<any>;
}