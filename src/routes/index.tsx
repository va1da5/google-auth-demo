import { createFileRoute } from "@tanstack/react-router";
import Markdown from "react-markdown";

export const Route = createFileRoute("/")({
  component: Index,
});

function Index() {
  return (
    <>
      <div className="prose mb-20">
        <Markdown>{`
*This is an example application which provides authentication to application using Google Auth provider.*

### The OAuth Authorization Code Flow for Google authentication involves the following steps:

1. **User Initiation**: The user initiates the login process by clicking a "Sign in with Google" button on your application.

2. **Redirect to Google**: Your application redirects the user to Google's OAuth 2.0 authorization endpoint, including parameters such as:

    - \`client_id\`: Your application's client ID.
    - \`redirect_uri\`: The URL where Google will send the user after authorization.
    - \`response_type\`: Set to code to indicate that you are requesting an authorization code.
    - \`scope\`: The permissions your application is requesting.
    - \`state\`: A unique string to maintain state between the request and callback.

3. **User Consent**: The user is prompted to log in to their Google account (if not already logged in) and to grant the requested permissions to your application.

4. **Authorization Code**: If the user consents, Google redirects the user back to your specified redirect_uri with an authorization code and the state parameter.

5. **Exchange Code for Tokens**: Your application receives the authorization code and makes a server-side request to Google's token endpoint, including:

    - \`client_id\`: Your application's client ID.
    - \`client_secret\`: Your application's client secret.
    - \`code\`: The authorization code received.
    - \`redirect_uri\`: The same redirect URI used in the initial request.
    - \`grant_type\`: Set to authorization_code.

6. **Access and Refresh Tokens**: Google responds with an access token and optionally a refresh token, which your application can use to access the user's Google resources on their behalf.

7. **Access Resources**: Your application can now use the access token to make authorized API requests to Google services.

This flow ensures that sensitive credentials are kept secure and that the user has control over the permissions granted to your application.
`}</Markdown>
      </div>
    </>
  );
}
