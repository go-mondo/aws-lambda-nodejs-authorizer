import { Logger } from "@aws-lambda-powertools/logger";
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

const logger = new Logger({
  logRecordOrder: ["level", "message"],
  serviceName: "mondo-rest-api-authorizer",
});

export const handler = createRestApiAuthorizerHandler();

export function createRestApiAuthorizerHandler(options: RestApiAuthorizerHandlerOptions = {}) {
  return async (event: APIGatewayTokenAuthorizerEvent): Promise<APIGatewayAuthorizerResult> => {
    try {
      const token = getBearerToken(event.authorizationToken);
      const { payload } = await verifyToken(token);

      logger.info("Token verified", { context: getSafeClaimLogContext(payload) });

      assertRequiredClaims(payload, getRequiredClaims());
      await validateCustomClaims(payload, options.validateClaims);

      const context = {
        ...buildDefaultContext(payload),
        ...buildMappedContext(payload, getContextClaims()),
        ...(await options.buildAdditionalContext?.(payload)),
      };
      const principalId = getClaim(payload, "sub") ?? "mondo-user";
      const result = authorizerResult({
        context,
        methodArn: event.methodArn,
        policyStatement: {
          ...getPolicyStatement(),
          ...(await options.buildPolicyStatement?.({
            claims: payload,
            methodArn: event.methodArn,
          })),
        },
        principalId,
      });

      logger.debug("Authorizer success", { output: result });

      return result;
    } catch (error) {
      if (!isUnauthorizedError(error)) {
        logger.error("Authorizer failed", { error });
      }

      throw error;
    }
  };
}

export function getBearerToken(authorizationToken?: string): string {
  const match = authorizationToken?.match(/^Bearer\s+(.+)$/i);

  if (!match?.[1]) {
    throw unauthorized("authorization_header_missing_or_malformed", {
      authorizationScheme: authorizationToken?.match(/^(\S+)/)?.[1],
      hasAuthorizationToken: Boolean(authorizationToken),
    });
  }

  const token = match[1].trim();

  if (!token) {
    throw unauthorized("authorization_header_missing_or_malformed", {
      authorizationScheme: authorizationToken?.match(/^(\S+)/)?.[1],
      hasAuthorizationToken: Boolean(authorizationToken),
    });
  }

  logger.debug("Bearer token extracted from authorization header", {
    token: {
      length: token.length,
    },
  });

  return token;
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
    logger.debug("Verifying JWT", {
      match: {
        audience,
        issuer: discovery.configuration.issuer,
      },
    });

    return await jwtVerify(token, discovery.jwks, verifyOptions);
  } catch (error) {
    if (isJwtVerificationFailure(error)) {
      throw unauthorized("jwt_verification_failed", getErrorLogContext(error));
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
        throw unauthorized("required_claim_values_missing", {
          actualValues: summarizeLogValue(actualValues),
          claimName,
          expectedValues: expected.map(String),
          missingExpectedValues: expected
            .map(String)
            .filter((value) => !actualValues.includes(value)),
        });
      }

      continue;
    }

    if (actual !== expected) {
      throw unauthorized("required_claim_mismatch", {
        actualValue: summarizeLogValue(actual),
        claimName,
        expectedValue: expected,
        hasClaim: actual !== undefined,
      });
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

export function buildAllMethodsResource(methodArn: string): string {
  const arnParts = methodArn.split(":");
  const executeApiResource = arnParts[5];

  if (!executeApiResource) {
    return methodArn;
  }

  const [apiId, stage] = executeApiResource.split("/");

  if (!apiId || !stage) {
    return methodArn;
  }

  arnParts[5] = `${apiId}/${stage}/*/*`;

  return arnParts.join(":");
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
    logger.debug("Using cached OIDC discovery configuration");

    return discoveryCache;
  }

  const idpDomainName = getRequiredEnv("MONDO_IDP_DOMAIN_NAME");
  const normalizedIdpDomainName = stripWrappingQuotes(idpDomainName);
  const discoveryUrl = `${normalizeIssuerBaseUrl(normalizedIdpDomainName)}/.well-known/openid-configuration`;

  logger.info("Fetching OIDC discovery configuration", {
    discoveryUrl,
    idpDomainName: normalizedIdpDomainName,
  });

  const response = await fetch(discoveryUrl);

  if (!response.ok) {
    logger.error("OIDC discovery request failed", {
      discoveryUrl,
      status: response.status,
    });

    throw new Error(`OIDC discovery request failed with status ${response.status}`);
  }

  const configuration = (await response.json()) as Partial<OpenIdConfiguration>;

  if (!configuration.issuer || !configuration.jwks_uri) {
    logger.error("OIDC discovery response is missing required fields", {
      hasIssuer: Boolean(configuration.issuer),
      hasJwksUri: Boolean(configuration.jwks_uri),
    });

    throw new Error("OIDC discovery response is missing issuer or jwks_uri");
  }

  discoveryCache = {
    configuration: {
      issuer: configuration.issuer,
      jwks_uri: configuration.jwks_uri,
    },
    jwks: createRemoteJWKSet(new URL(configuration.jwks_uri)),
  };

  logger.info("OIDC discovery configuration loaded", {
    issuer: discoveryCache.configuration.issuer,
    jwksUri: discoveryCache.configuration.jwks_uri,
  });

  return discoveryCache;
}

function getAudience(): string | string[] {
  const rawAudience = stripWrappingQuotes(getRequiredEnv("MONDO_AUDIENCE"));

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
  } catch (error) {
    throw unauthorized("custom_claim_validation_failed", {
      ...getSafeClaimLogContext(claims),
      ...getErrorLogContext(error),
    });
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

  try {
    return JSON.parse(rawValue) as T;
  } catch (error) {
    logger.error("Environment variable contains invalid JSON", {
      ...getErrorLogContext(error),
      envName: name,
    });

    throw error;
  }
}

function getRequiredEnv(name: string): string {
  const value = process.env[name];

  if (!value) {
    logger.error("Required environment variable is missing", {
      envName: name,
    });

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

function stripWrappingQuotes(value: string): string {
  const trimmedValue = value.trim();

  if (
    (trimmedValue.startsWith('"') && trimmedValue.endsWith('"')) ||
    (trimmedValue.startsWith("'") && trimmedValue.endsWith("'"))
  ) {
    return trimmedValue.slice(1, -1);
  }

  return trimmedValue;
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

function getSafeClaimLogContext(claims: JWTPayload): Record<string, string> {
  return compactContext({
    appId: getClaim(claims, "azp"),
    audience: getClaim(claims, "aud"),
    issuer: getClaim(claims, "iss"),
    subject: getClaim(claims, "sub"),
    tenantId: getClaim(claims, "tnt"),
  });
}

function getErrorLogContext(error: unknown): Record<string, unknown> {
  if (!(error instanceof Error)) {
    return { error };
  }

  return compactContext({
    errorClaim: getUnknownProperty(error, "claim"),
    errorCode: getUnknownProperty(error, "code"),
    errorMessage: error.message,
    errorName: error.name,
    errorReason: getUnknownProperty(error, "reason"),
  });
}

function getUnknownProperty(value: object, key: string): string | undefined {
  const propertyValue = (value as Record<string, unknown>)[key];

  return typeof propertyValue === "string" ? propertyValue : undefined;
}

function summarizeLogValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => summarizeLogValue(item));
  }

  if (
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean" ||
    value === undefined ||
    value === null
  ) {
    return value;
  }

  return `[${typeof value}]`;
}

function isUnauthorizedError(error: unknown): boolean {
  return error instanceof Error && error.message === "Unauthorized";
}

function unauthorized(reason: string, attributes: Record<string, unknown> = {}): Error {
  logger.warn("REST API authorizer request denied", {
    ...attributes,
    reason,
  });

  return new Error("Unauthorized");
}
