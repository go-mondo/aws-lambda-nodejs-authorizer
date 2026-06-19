import { App, Duration, Stack } from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import { RestApi } from "aws-cdk-lib/aws-apigateway";
import { describe, expect, it } from "vitest";
import { MondoAuthorizer, MondoAuthorizerHandler } from "./construct.js";

describe("MondoAuthorizer", () => {
  it("creates a REST API token authorizer for an explicit Lambda handler", () => {
    const app = new App();
    const stack = new Stack(app, "TestStack");

    const handler = new MondoAuthorizerHandler(stack, "MondoAuthorizerHandler", {
      additionalContextClaims: {
        scopes: "scope",
      },
      audience: "https://app.mondoidentity.com",
      environment: {
        EXPECTED_MONDO_APP_ID: "app_123",
      },
      domainName: "mondo.auth.mondoidentity.com",
      idpRequestTimeout: Duration.millis(1500),
      requiredClaims: {
        scope: ["openid", "email"],
      },
    });
    handler.addEnvironment("CUSTOM_VALIDATION_MODE", "strict");

    const authorizer = new MondoAuthorizer(stack, "MondoAuthorizer", {
      handler,
    });

    const api = new RestApi(stack, "Api");
    api.root.addMethod("GET", undefined, {
      authorizer,
    });

    const template = Template.fromStack(stack);

    template.hasResourceProperties("AWS::Lambda::Function", {
      Environment: {
        Variables: {
          MONDO_AUDIENCE: "https://app.mondoidentity.com",
          MONDO_CONTEXT_CLAIMS: '{"scopes":"scope"}',
          MONDO_IDP_DOMAIN_NAME: "mondo.auth.mondoidentity.com",
          MONDO_IDP_REQUEST_TIMEOUT_MS: "1500",
          MONDO_REQUIRED_CLAIMS: '{"scope":["openid","email"]}',
          CUSTOM_VALIDATION_MODE: "strict",
          EXPECTED_MONDO_APP_ID: "app_123",
        },
      },
      Runtime: "nodejs24.x",
    });

    template.resourceCountIs("AWS::ApiGateway::Authorizer", 1);
    expect(authorizer.authorizerId).toBeDefined();
  });
});
