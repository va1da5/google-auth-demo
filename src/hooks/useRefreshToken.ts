import axios from "../api/axios";
import useAuth from "./useAuth";
import { useNavigate } from "@tanstack/react-router";

const useRefreshToken = () => {
  const { auth, setAuth } = useAuth();
  const navigate = useNavigate();

  const refresh = async () => {
    try {
      const response = await axios.post("/token/refresh", {
        refreshToken: auth.refresh,
      });

      setAuth((current) => {
        return { ...current, access: response.data.accessToken };
      });
      return response.data.accessToken;
    } catch (error) {
      console.log(error);

      setAuth((current) => ({
        ...current,
        active: false,
        access: "",
        refresh: "",
      }));

      navigate({ to: "/logout" });
      return "";
    }
  };
  return refresh;
};

export default useRefreshToken;
