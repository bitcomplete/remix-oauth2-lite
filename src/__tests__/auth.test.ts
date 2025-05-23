import { createCookieSessionStorage } from "@remix-run/node";
import { Auth } from "../index";
import OAuth2Provider from "../providers/oauth2";

describe("Auth", () => {
  const sessionStorage = createCookieSessionStorage({
    cookie: {
      name: "test-session",
      secrets: ["test-secret"],
      sameSite: "lax",
    },
  });

  const mockProvider = new OAuth2Provider({
    name: "test",
    authorizationUrl: "https://test.com/oauth/authorize",
    tokenUrl: "https://test.com/oauth/token",
    clientId: "test-client-id",
  });

  const auth = new Auth({
    sessionStorage,
    providers: [mockProvider],
  });

  it("should initialize with providers", () => {
    expect(auth).toBeDefined();
  });

  it("should handle logout", async () => {
    const request = new Request("http://test.com/auth/test/logout");
    try {
      await auth.loader({ 
        request, 
        params: {},
        context: {} 
      });
      fail("Expected a redirect response");
    } catch (error) {
      expect(error).toBeInstanceOf(Response);
      if (error instanceof Response) {
        expect(error.status).toBe(302);
        expect(error.headers.get("Location")).toBe("/");
      }
    }
  });
}); 