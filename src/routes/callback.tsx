import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { getTokens } from "../utils";
import useAuth from "../hooks/useAuth";
import { useEffect } from "react";

export const Route = createFileRoute("/callback")({
  component: Callback,
});

type QueryParams = {
  code?: string;
};

function Callback() {
  const searchParams: QueryParams = Route.useSearch();
  const navigate = useNavigate({ from: "/callback" });
  const { setAuth } = useAuth();

  useEffect(() => {
    (async () => {
      if (!searchParams?.code) {
        return navigate({
          to: "/login",
        });
      }

      const token = await getTokens(searchParams?.code);

      if (
        !token.accessToken ||
        !token.accessToken.length ||
        !token.refreshToken ||
        !token.refreshToken.length
      ) {
        navigate({
          to: "/login",
        });
        return;
      }

      setAuth({
        access: token.accessToken,
        refresh: token.refreshToken,
        active: true,
      });

      navigate({
        to: "/",
      });
    })();
  }, []);

  return <>Redirecting..</>;
}
