import { axiosAuthorized } from "../api/axios";
import { useEffect } from "react";
import useRefreshToken from "./useRefreshToken";
import useAuth from "./useAuth";

const useAxiosAuthorized = () => {
  const refresh = useRefreshToken();
  const { auth } = useAuth();

  useEffect(() => {
    const requestIntercept = axiosAuthorized.interceptors.request.use(
      (config) => {
        if (!config.headers["Authorization"]) {
          config.headers["Authorization"] = `Bearer ${auth?.access}`;
        }
        return config;
      },
      (error) => Promise.reject(error),
    );

    const responseIntercept = axiosAuthorized.interceptors.response.use(
      (response) => response,
      async (error) => {
        const prevRequest = error?.config;
        if (error?.response?.status === 403 && !prevRequest?.sent) {
          prevRequest.sent = true;
          const newAccessToken = await refresh();
          prevRequest.headers["Authorization"] = `Bearer ${newAccessToken}`;
          return axiosAuthorized(prevRequest);
        }
        return Promise.reject(error);
      },
    );

    return () => {
      axiosAuthorized.interceptors.request.eject(requestIntercept);
      axiosAuthorized.interceptors.response.eject(responseIntercept);
    };
  }, [auth, refresh]);

  return axiosAuthorized;
};

export default useAxiosAuthorized;
