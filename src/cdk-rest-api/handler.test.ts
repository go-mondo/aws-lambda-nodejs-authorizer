import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";

const { logger } = vi.hoisted(() => ({
  logger: {
    debug: vi.fn(),
    error: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
  },
}));

vi.mock("@aws-lambda-powertools/logger", () => ({
  Logger: vi.fn().mockImplementation(() => logger),
}));

import {
  assertRequiredClaims,
  buildAllMethodsResource,
  buildDefaultContext,
  buildMappedContext,
  createRestApiAuthorizerHandler,
  getBearerToken,
  getClaim,
  getScopes,
  verifyToken,
} from "./handler.js";

describe("REST API authorizer helpers", () => {
  afterEach(() => {
    vi.clearAllMocks();
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
    expect(() => getBearerToken("Bearer    ")).toThrow("Unauthorized");
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

  it("builds an execute-api resource that covers all methods in the stage", () => {
    expect(
      buildAllMethodsResource(
        "arn:aws:execute-api:us-east-1:123456789012:a1b2c3d4e5/prod/GET/customers/123",
      ),
    ).toBe("arn:aws:execute-api:us-east-1:123456789012:a1b2c3d4e5/prod/*/*");
  });

  it("keeps malformed method ARNs unchanged when an all-methods resource cannot be built", () => {
    expect(buildAllMethodsResource("arn:aws:execute-api:us-east-1:123456789012")).toBe(
      "arn:aws:execute-api:us-east-1:123456789012",
    );
    expect(buildAllMethodsResource("arn:aws:execute-api:us-east-1:123456789012:a1b2c3d4e5")).toBe(
      "arn:aws:execute-api:us-east-1:123456789012:a1b2c3d4e5",
    );
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
    process.env.MONDO_AUDIENCE = "https://app.mondoidentity.com";
    process.env.MONDO_IDP_DOMAIN_NAME = '"mondo.auth.mondoidentity.com"';
    const fetch = vi.fn(async () =>
      Response.json({
        issuer: "https://mondo.auth.mondoidentity.com",
        jwks_uri: "https://mondo.auth.mondoidentity.com/.well-known/jwks.json",
      }),
    );
    vi.stubGlobal("fetch", fetch);

    await expect(verifyToken("not-a-jwt")).rejects.toThrow("Unauthorized");
    expect(fetch).toHaveBeenCalledWith(
      "https://mondo.auth.mondoidentity.com/.well-known/openid-configuration",
    );
  });

  it("does not log values returned in additional authorizer context", async () => {
    const issuer = "https://mondo.auth.mondoidentity.com";
    const audience = "https://app.mondoidentity.com";
    const methodArn =
      "arn:aws:execute-api:us-east-1:123456789012:a1b2c3d4e5/prod/GET/customers/123";
    const secret = "do-not-log";
    const { privateKey, publicKey } = await generateKeyPair("ES256");
    const publicJwk = {
      ...(await exportJWK(publicKey)),
      alg: "ES256",
      kid: "test-key",
      use: "sig",
    };
    const token = await new SignJWT({ azp: "app_123", tnt: "tnt_123" })
      .setProtectedHeader({ alg: "ES256", kid: "test-key" })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject("usr_123")
      .setExpirationTime("5m")
      .sign(privateKey);
    const fetch = vi.fn(async (input: string | URL | Request) => {
      const url = String(input);

      return url.endsWith("/.well-known/openid-configuration")
        ? Response.json({ issuer, jwks_uri: `${issuer}/.well-known/jwks.json` })
        : Response.json({ keys: [publicJwk] });
    });
    vi.stubGlobal("fetch", fetch);
    process.env.MONDO_AUDIENCE = audience;
    process.env.MONDO_IDP_DOMAIN_NAME = "mondo.auth.mondoidentity.com";
    logger.debug.mockClear();

    const handler = createRestApiAuthorizerHandler({
      buildAdditionalContext: () => ({ sensitiveValue: secret }),
    });
    const result = await handler({
      authorizationToken: `Bearer ${token}`,
      methodArn,
      type: "TOKEN",
    });

    expect(result.context).toMatchObject({ sensitiveValue: secret });
    expect(logger.debug).toHaveBeenCalledWith("Authorizer success", { methodArn });
    expect(
      JSON.stringify([
        logger.debug.mock.calls,
        logger.error.mock.calls,
        logger.info.mock.calls,
        logger.warn.mock.calls,
      ]),
    ).not.toContain(secret);
  });
});
