import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Duration } from "aws-cdk-lib";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import * as lambda from "aws-cdk-lib/aws-lambda";
import {
  type BundlingOptions,
  NodejsFunction,
  type NodejsFunctionProps,
  OutputFormat,
} from "aws-cdk-lib/aws-lambda-nodejs";
import type { Construct } from "constructs";
import type { ClaimExpectation, PolicyStatementOverride } from "./handler.js";

export type MondoAuthorizerProps = apigateway.TokenAuthorizerProps;

export interface MondoAuthorizerHandlerProps extends NodejsFunctionProps {
  /**
   * Mondo IdP domain or URL used to discover OpenID Provider metadata.
   *
   * Examples: `mondo.auth.mondoidentity.com` or `https://mondo.auth.mondoidentity.com`.
   */
  readonly domainName?: string;

  /**
   * Expected JWT audience. Passed to jose's JWT verification options.
   */
  readonly audience?: string | string[];

  /**
   * Additional exact-match claim requirements evaluated after JWT verification.
   *
   * Arrays mean the JWT claim must contain every configured value. This works for either array
   * claims or space-delimited string claims such as `scope`.
   */
  readonly requiredClaims?: Record<string, ClaimExpectation>;

  /**
   * Additional context values to return from the authorizer.
   *
   * Keys become API Gateway context keys. Values are JWT claim paths, such as `email` or
   * `https://example.com/custom_claim`.
   */
  readonly additionalContextClaims?: Record<string, string>;

  /**
   * Overrides the IAM policy statement returned by the packaged authorizer Lambda.
   *
   * Omitted fields use secure defaults: `execute-api:Invoke`, `Allow`, and the incoming
   * `event.methodArn`.
   */
  readonly policyStatement?: PolicyStatementOverride;
}

export class MondoAuthorizerHandler extends NodejsFunction {
  public constructor(scope: Construct, id: string, props: MondoAuthorizerHandlerProps = {}) {
    const defaultBundling: BundlingOptions = {
      banner:
        "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);",
      format: OutputFormat.ESM,
      mainFields: ["module", "main"],
      minify: true,
      sourceMap: true,
      target: "node24",
    };

    super(scope, id, {
      ...props,
      bundling: {
        ...defaultBundling,
        ...props.bundling,
      },
      entry: props.entry ?? defaultAuthorizerEntry(),
      environment: {
        ...buildMondoEnvironment(props),
        ...props.environment,
      },
      handler: props.handler ?? "handler",
      runtime: props.runtime ?? lambda.Runtime.NODEJS_24_X,
    });
  }
}

export class MondoAuthorizer extends apigateway.TokenAuthorizer {
  public constructor(scope: Construct, id: string, props: MondoAuthorizerProps) {
    super(scope, id, {
      identitySource: apigateway.IdentitySource.header("Authorization"),
      resultsCacheTtl: Duration.minutes(5),
      ...props,
    });
  }
}

function buildMondoEnvironment(props: MondoAuthorizerHandlerProps): Record<string, string> {
  const environment: Record<string, string> = {};

  if (props.audience) {
    environment.MONDO_AUDIENCE = JSON.stringify(props.audience);
  }

  if (props.domainName) {
    environment.MONDO_IDP_DOMAIN_NAME = props.domainName;
  }

  if (props.requiredClaims) {
    environment.MONDO_REQUIRED_CLAIMS = JSON.stringify(props.requiredClaims);
  }

  if (props.additionalContextClaims) {
    environment.MONDO_CONTEXT_CLAIMS = JSON.stringify(props.additionalContextClaims);
  }

  if (props.policyStatement) {
    environment.MONDO_POLICY_STATEMENT = JSON.stringify(props.policyStatement);
  }

  return environment;
}

function defaultAuthorizerEntry(): string {
  const currentDirectory = dirname(fileURLToPath(import.meta.url));

  return join(currentDirectory, "../../src/cdk-rest-api/handler.ts");
}
