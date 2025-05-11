import axios from "./api/axios";

export function getUrl() {
  const params = {
    client_id: import.meta.env.VITE_GOOGLE_CLIENT_ID,
    scope: import.meta.env.VITE_GOOGLE_SCOPE,
    response_type: "code",
    redirect_uri: import.meta.env.VITE_GOOGLE_REDIRECT_URI,
  };

  const url = new URL(import.meta.env.VITE_OIDC_CLIENT_AUTH_URI);
  Object.keys(params).forEach((key) => {
    url.searchParams.append(key, params[key as keyof typeof params]);
  });

  return url.toString();
}

export async function getTokens(code: string) {
  const response = await axios.get("/token", {
    params: { code },
  });

  return response.data;
}
