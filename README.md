# 🛂 Google Auth DEMO

This is an example application that provides authentication to the application using the Google Auth provider.

## OpenID Connect Sign-In Steps

According to [the official documentation](https://developers.google.com/identity/protocols/oauth2/web-server#obtainingaccesstokens).

```bash
# 1. Create and open a sign-in link in a browser
https://accounts.google.com/o/oauth2/auth?client_id=some-speicifc-client-id.apps.googleusercontent.com&response_type=code&scope=https://www.googleapis.com/auth/userinfo.profile%20https://www.googleapis.com/auth/userinfo.email%20openid&redirect_uri=http://localhost:5173/callback&access_type=offline&include_granted_scopes=true


# 2. Once user consents and approves sign-in, handle returned parameters
http://localhost:5173/callback?code=4%2F0Ab_5qlnVQliPeNoRN2BoQvnAK1A_89fLRfk3JI9QHz-HSGXMTXB-JZyf-aXkbDxBr9nJEw&scope=email+profile+openid+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile&authuser=0&prompt=none

# 3. Exchange the 'code' using the client_secret. The following needs to be done in a backend system.
curl --request POST \
  --url https://oauth2.googleapis.com/token \
  --header 'content-type: application/x-www-form-urlencoded' \
  --data client_id=some-speicifc-client-id.apps.googleusercontent.com \
  --data client_secret=GOOGLE-BZAlcgYZ3PX7FNCao-be5knAjRZA \
  --data grant_type=authorization_code \
  --data 'redirect_uri="http://localhost:5173/callback"' \
  --data code=4/0Ab_5qlk4PVzC2feZRnFh3VIiZ0f9Gie_HbQtK5rxzoXLxfGR7dCfu7x1HaZPZRkRH2PXAA | jq

# 4. Handle returned tokens as you see fit, preferably in a secure manner.
```

## Development

```bash
# 1. Clone this repository

# 2. Fetch required dependencies
pnpm install

# 3. Get OAuth client for the app while following https://developers.google.com/identity/openid-connect/openid-connect guide

# 4. Configure .env file and update values
cp sample.env .env

# 5. Start backend server
pnpm run backend

# 6. Start frontend
pnpm run dev

# 7. Debug and get it working
```

## 📚 References

- [How to create Google OAuth Client](https://developers.google.com/identity/openid-connect/openid-connect)
- [OAuth 2.0 Authorization Framework](https://auth0.com/docs/authenticate/protocols/oauth)
- [Obtaining OAuth 2.0 access tokens](https://developers.google.com/identity/protocols/oauth2/web-server#obtainingaccesstokens)
- [Standard OAuth 2.0 / OpenID Connect endpoints](https://connect2id.com/products/server/docs/api)
- [OAuth 2.0 Scopes for Google APIs](https://developers.google.com/identity/protocols/oauth2/scopes)
- [JSON Web Token (JWT) Debugger](https://jwt.io/)
- [JSON Web Token Claims](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-token-claims)
- [Google OAuth 2.0 Playground](https://developers.google.com/oauthplayground/)
- [Verifying the User Info](https://www.oauth.com/oauth2-servers/signing-in-with-google/verifying-the-user-info/)
- [TanStack Router](https://tanstack.com/router/latest/docs/framework/react/overview)
- [React Login Authentication with JWT Access, Refresh Tokens, Cookies and Axios](https://www.youtube.com/watch?v=nI8PYZNFtac)
- [gitdagray/react_jwt_auth](https://github.com/gitdagray/react_jwt_auth)
