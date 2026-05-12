import { afterEach, describe, expect, it, vi } from "vitest";
import {
  assertRequiredClaims,
  buildDefaultContext,
  buildMappedContext,
  getBearerToken,
  getClaim,
  getScopes,
  verifyToken,
} from "./handler.js";

describe("REST API authorizer helpers", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.MONDO_AUDIENCE;
    delete process.env.MONDO_IDP_DOMAIN_NAME;
  });

  it("extracts bearer tokens", () => {
    expect(getBearerToken("Bearer abc.def.ghi")).toBe("abc.def.ghi");
    expect(getBearerToken("bearer token")).toBe("token");
  });

  it("rejects missing bearer tokens as Unauthorized", () => {
    expect(() => getBearerToken("Token abc")).toThrow("Unauthorized");
  });

  it("builds default Mondo context from token claims", () => {
    expect(
      buildDefaultContext({
        azp: "app_123",
        sub: "usr_123",
        tnt: "tnt_123",
      }),
    ).toEqual({
      appId: "app_123",
      tenantId: "tnt_123",
      userId: "usr_123",
    });
  });

  it("maps additional context claims", () => {
    expect(
      buildMappedContext(
        {
          email: "user@example.com",
          roles: ["admin", "operator"],
        },
        {
          email: "email",
          roles: "roles",
        },
      ),
    ).toEqual({
      email: "user@example.com",
      roles: "admin operator",
    });
  });

  it("reads claims as context-safe strings", () => {
    const claims = {
      enabled: true,
      email: "user@example.com",
      roles: ["admin", "operator"],
      version: 2,
    };

    expect(getClaim(claims, "email")).toBe("user@example.com");
    expect(getClaim(claims, "roles")).toBe("admin operator");
    expect(getClaim(claims, "version")).toBe("2");
    expect(getClaim(claims, "enabled")).toBe("true");
    expect(getClaim(claims, "missing")).toBeUndefined();
  });

  it("reads scopes from string or array claims", () => {
    expect(getScopes({ scope: "openid profile email" })).toEqual(["openid", "profile", "email"]);
    expect(getScopes({ permissions: ["api:read", "api:write"] }, "permissions")).toEqual([
      "api:read",
      "api:write",
    ]);
    expect(getScopes({})).toEqual([]);
  });

  it("validates required claims", () => {
    expect(() =>
      assertRequiredClaims(
        {
          scope: "openid profile email",
          tnt: "tnt_123",
        },
        {
          scope: ["openid", "email"],
          tnt: "tnt_123",
        },
      ),
    ).not.toThrow();
  });

  it("rejects missing required claim values", () => {
    expect(() =>
      assertRequiredClaims(
        {
          scope: "openid profile",
        },
        {
          scope: ["email"],
        },
      ),
    ).toThrow("Unauthorized");
  });

  it("normalizes JWT verification failures to Unauthorized", async () => {
    process.env.MONDO_AUDIENCE = '"https://app.mondoidentity.com"';
    process.env.MONDO_IDP_DOMAIN_NAME = "mondo.auth.mondoidentity.com";
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({
          issuer: "https://mondo.auth.mondoidentity.com",
          jwks_uri: "https://mondo.auth.mondoidentity.com/.well-known/jwks.json",
        }),
      ),
    );

    await expect(verifyToken("not-a-jwt")).rejects.toThrow("Unauthorized");
  });
});
