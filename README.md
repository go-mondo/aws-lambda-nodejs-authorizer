# @go-mondo/aws-lambda-nodejs-authorizer

AWS Lambda Node.js authorizers for Mondo Identity.

## CDK REST API

Create the authorizer Lambda and wire it into API Gateway.

```ts
import { Duration } from "aws-cdk-lib";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
import {
  MondoAuthorizer,
  MondoAuthorizerHandler,
} from "@go-mondo/aws-lambda-nodejs-authorizer/cdk-rest-api";

const authorizerHandler = new MondoAuthorizerHandler(this, "MondoAuthorizerHandler", {
  additionalContextClaims: {
    scopes: "scope",
  },
  audience: "https://app.mondoidentity.com",
  mondoIdpDomainName: "mondo.auth.mondoidentity.com",
  requiredClaims: {
    scope: ["openid", "email"],
  },
});
authorizerHandler.addEnvironment("EXPECTED_MONDO_APP_ID", "app_123");

const authorizer = new MondoAuthorizer(this, "MondoAuthorizer", {
  handler: authorizerHandler,
  resultsCacheTtl: Duration.minutes(5),
});

new apigateway.RestApi(this, "Api").root.addMethod("GET", integration, {
  authorizationType: apigateway.AuthorizationType.CUSTOM,
  authorizer,
});
```

`MondoAuthorizer` is a thin `apigateway.TokenAuthorizer` subclass with Mondo-friendly defaults, and
`MondoAuthorizerHandler` is a `NodejsFunction` helper with Node.js 24, ESM bundling, and the packaged
handler entry configured by default. The Lambda handler parses bearer tokens, discovers issuer and
JWKS metadata from `/.well-known/openid-configuration`, verifies JWTs with `jose`, validates issuer,
audience, and expiration, then returns `tenantId`, `appId`, and `userId` in the authorizer context.

Additional claim validation can be configured through `MONDO_REQUIRED_CLAIMS`, additional context
values can be mapped through `MONDO_CONTEXT_CLAIMS`, and the returned IAM statement can be
customized with `MONDO_POLICY_STATEMENT`.

## Custom Handler

Use the handler factory when your API needs custom validation, context, or policy decisions. The
factory still handles bearer-token parsing, OIDC discovery, JWKS lookup, and JWT verification before
your callbacks run.

```ts
import {
  createRestApiAuthorizerHandler,
  getClaim,
  getScopes,
} from "@go-mondo/aws-lambda-nodejs-authorizer/cdk-rest-api/handler";

export const handler = createRestApiAuthorizerHandler({
  validateClaims: async (claims) => {
    const tenantId = getClaim(claims, "tnt");
    const appId = getClaim(claims, "azp");

    if (!tenantId?.startsWith("tnt_")) {
      throw new Error("Unauthorized");
    }

    if (appId !== process.env.EXPECTED_MONDO_APP_ID) {
      throw new Error("Unauthorized");
    }
  },
  buildAdditionalContext: async (claims) => ({
    email: getClaim(claims, "email"),
    scopes: getClaim(claims, "scope"),
    tenantRegion: getClaim(claims, "https://example.com/tenant_region"),
  }),
  buildPolicyStatement: async ({ claims, methodArn }) => {
    const scopes = getScopes(claims);
    const isWriteRequest = methodArn.includes("/POST/") || methodArn.includes("/PUT/");
    const canWrite = scopes.includes("api:write");

    return {
      effect: isWriteRequest && !canWrite ? "Deny" : "Allow",
      resource: methodArn,
    };
  },
});
```

Then point the helper construct at your custom entry. Any `NodejsFunction` prop can still be
overridden.

```ts
const authorizerHandler = new MondoAuthorizerHandler(this, "MondoAuthorizerHandler", {
  entry: "src/authorizers/mondo-rest-api-handler.ts",
  environment: {
    EXPECTED_MONDO_APP_ID: "app_123",
  },
  mondoIdpDomainName: "mondo.auth.mondoidentity.com",
  audience: "https://app.mondoidentity.com",
});
```
