import type { APIGatewayAuthorizerResult, APIGatewayTokenAuthorizerEvent } from "aws-lambda";
import {
  createRemoteJWKSet,
  errors,
  type JWTPayload,
  type JWTVerifyOptions,
  jwtVerify,
} from "jose";

export type ClaimExpectation = string | number | boolean | string[] | number[] | boolean[];

export interface RestApiAuthorizerHandlerOptions {
  readonly validateClaims?: (claims: JWTPayload) => void | Promise<void>;
  readonly buildAdditionalContext?: (
    claims: JWTPayload,
  ) =>
    | Record<string, string | number | boolean | undefined>
    | Promise<Record<string, string | number | boolean | undefined>>;
  readonly buildPolicyStatement?: (input: {
    readonly claims: JWTPayload;
    readonly methodArn: string;
  }) => PolicyStatementOverride | Promise<PolicyStatementOverride>;
}

export interface PolicyStatementOverride {
  readonly action?: string | string[];
  readonly effect?: "Allow" | "Deny";
  readonly resource?: string | string[];
}

interface OpenIdConfiguration {
  readonly issuer: string;
  readonly jwks_uri: string;
}

interface DiscoveryCacheEntry {
  readonly configuration: OpenIdConfiguration;
  readonly jwks: ReturnType<typeof createRemoteJWKSet>;
}

let discoveryCache: DiscoveryCacheEntry | undefined;

export const handler = createRestApiAuthorizerHandler();

export function createRestApiAuthorizerHandler(options: RestApiAuthorizerHandlerOptions = {}) {
  return async (event: APIGatewayTokenAuthorizerEvent): Promise<APIGatewayAuthorizerResult> => {
    const token = getBearerToken(event.authorizationToken);
    const { payload } = await verifyToken(token);

    assertRequiredClaims(payload, getRequiredClaims());
    await validateCustomClaims(payload, options.validateClaims);

    return authorizerResult({
      context: {
        ...buildDefaultContext(payload),
        ...buildMappedContext(payload, getContextClaims()),
        ...(await options.buildAdditionalContext?.(payload)),
      },
      methodArn: event.methodArn,
      policyStatement: {
        ...getPolicyStatement(),
        ...(await options.buildPolicyStatement?.({
          claims: payload,
          methodArn: event.methodArn,
        })),
      },
      principalId: getClaim(payload, "sub") ?? "mondo-user",
    });
  };
}

export function getBearerToken(authorizationToken?: string): string {
  const match = authorizationToken?.match(/^Bearer\s+(.+)$/i);

  if (!match?.[1]) {
    throw unauthorized();
  }

  return match[1].trim();
}

export async function verifyToken(token: string) {
  const discovery = await getDiscovery();
  const audience = getAudience();
  const verifyOptions: JWTVerifyOptions = {
    audience,
    issuer: discovery.configuration.issuer,
    requiredClaims: ["exp"],
  };

  try {
    return await jwtVerify(token, discovery.jwks, verifyOptions);
  } catch (error) {
    if (isJwtVerificationFailure(error)) {
      throw unauthorized();
    }

    throw error;
  }
}

export function assertRequiredClaims(
  claims: JWTPayload,
  requiredClaims: Record<string, ClaimExpectation>,
): void {
  for (const [claimName, expected] of Object.entries(requiredClaims)) {
    const actual = claims[claimName];

    if (Array.isArray(expected)) {
      const actualValues = normalizeClaimValues(actual);
      const hasEveryValue = expected.every((value) => actualValues.includes(String(value)));

      if (!hasEveryValue) {
        throw unauthorized();
      }

      continue;
    }

    if (actual !== expected) {
      throw unauthorized();
    }
  }
}

export function buildDefaultContext(claims: JWTPayload): Record<string, string> {
  return compactContext({
    appId: getClaim(claims, "azp"),
    tenantId: getClaim(claims, "tnt"),
    userId: getClaim(claims, "sub"),
  });
}

export function buildMappedContext(
  claims: JWTPayload,
  claimMappings: Record<string, string>,
): Record<string, string> {
  const context: Record<string, string | undefined> = {};

  for (const [contextKey, claimName] of Object.entries(claimMappings)) {
    context[contextKey] = stringifyContextValue(claims[claimName]);
  }

  return compactContext(context);
}

export function getClaim(
  claims: JWTPayload | Record<string, unknown>,
  claimName: string,
): string | undefined {
  return stringifyContextValue(claims[claimName]);
}

export function getScopes(
  claims: JWTPayload | Record<string, unknown>,
  claimName = "scope",
): string[] {
  return normalizeClaimValues(claims[claimName]);
}

function authorizerResult(input: {
  readonly context: Record<string, string | number | boolean | undefined>;
  readonly methodArn: string;
  readonly policyStatement?: PolicyStatementOverride;
  readonly principalId: string;
}): APIGatewayAuthorizerResult {
  const policyStatement = input.policyStatement ?? {};

  return {
    context: compactContext(input.context),
    policyDocument: {
      Statement: [
        {
          Action: policyStatement.action ?? "execute-api:Invoke",
          Effect: policyStatement.effect ?? "Allow",
          Resource: policyStatement.resource ?? input.methodArn,
        },
      ],
      Version: "2012-10-17",
    },
    principalId: input.principalId,
  };
}

async function getDiscovery(): Promise<DiscoveryCacheEntry> {
  if (discoveryCache) {
    return discoveryCache;
  }

  const idpDomainName = getRequiredEnv("MONDO_IDP_DOMAIN_NAME");
  const discoveryUrl = `${normalizeIssuerBaseUrl(idpDomainName)}/.well-known/openid-configuration`;
  const response = await fetch(discoveryUrl);

  if (!response.ok) {
    throw new Error(`OIDC discovery request failed with status ${response.status}`);
  }

  const configuration = (await response.json()) as Partial<OpenIdConfiguration>;

  if (!configuration.issuer || !configuration.jwks_uri) {
    throw new Error("OIDC discovery response is missing issuer or jwks_uri");
  }

  discoveryCache = {
    configuration: {
      issuer: configuration.issuer,
      jwks_uri: configuration.jwks_uri,
    },
    jwks: createRemoteJWKSet(new URL(configuration.jwks_uri)),
  };

  return discoveryCache;
}

function getAudience(): string | string[] {
  const rawAudience = getRequiredEnv("MONDO_AUDIENCE");

  try {
    const parsedAudience = JSON.parse(rawAudience) as unknown;

    if (typeof parsedAudience === "string") {
      return parsedAudience;
    }

    if (Array.isArray(parsedAudience) && parsedAudience.every((item) => typeof item === "string")) {
      return parsedAudience;
    }
  } catch {
    return rawAudience;
  }

  throw new Error("MONDO_AUDIENCE must be a string or string array");
}

function getRequiredClaims(): Record<string, ClaimExpectation> {
  return parseJsonEnv<Record<string, ClaimExpectation>>("MONDO_REQUIRED_CLAIMS") ?? {};
}

function getContextClaims(): Record<string, string> {
  return parseJsonEnv<Record<string, string>>("MONDO_CONTEXT_CLAIMS") ?? {};
}

function getPolicyStatement(): PolicyStatementOverride {
  return parseJsonEnv<PolicyStatementOverride>("MONDO_POLICY_STATEMENT") ?? {};
}

async function validateCustomClaims(
  claims: JWTPayload,
  validateClaims?: RestApiAuthorizerHandlerOptions["validateClaims"],
): Promise<void> {
  try {
    await validateClaims?.(claims);
  } catch {
    throw unauthorized();
  }
}

function isJwtVerificationFailure(error: unknown): boolean {
  return (
    error instanceof errors.JWTClaimValidationFailed ||
    error instanceof errors.JWTExpired ||
    error instanceof errors.JWTInvalid ||
    error instanceof errors.JWSInvalid ||
    error instanceof errors.JWSSignatureVerificationFailed ||
    error instanceof errors.JOSEAlgNotAllowed ||
    error instanceof errors.JWKSNoMatchingKey
  );
}

function parseJsonEnv<T>(name: string): T | undefined {
  const rawValue = process.env[name];

  if (!rawValue) {
    return undefined;
  }

  return JSON.parse(rawValue) as T;
}

function getRequiredEnv(name: string): string {
  const value = process.env[name];

  if (!value) {
    throw new Error(`${name} is required`);
  }

  return value;
}

function normalizeIssuerBaseUrl(idpDomainName: string): string {
  const trimmedValue = idpDomainName.trim().replace(/\/+$/, "");

  if (trimmedValue.startsWith("https://") || trimmedValue.startsWith("http://")) {
    return trimmedValue;
  }

  return `https://${trimmedValue}`;
}

function stringifyContextValue(value: unknown): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }

  if (typeof value === "string") {
    return value;
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }

  if (Array.isArray(value)) {
    return value.map((item) => String(item)).join(" ");
  }

  return undefined;
}

function normalizeClaimValues(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.map((item) => String(item));
  }

  if (typeof value === "string") {
    return value.split(/\s+/).filter(Boolean);
  }

  if (value === undefined || value === null) {
    return [];
  }

  return [String(value)];
}

function compactContext<T extends string | number | boolean>(
  context: Record<string, T | undefined>,
): Record<string, T> {
  return Object.fromEntries(
    Object.entries(context).filter((entry): entry is [string, T] => entry[1] !== undefined),
  );
}

function unauthorized(): Error {
  return new Error("Unauthorized");
}
