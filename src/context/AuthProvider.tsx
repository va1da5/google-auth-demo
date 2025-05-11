import {
  createContext,
  useEffect,
  useState,
  type ReactNode,
  type SetStateAction,
} from "react";

type AuthState = {
  access: string;
  refresh: string;
  active: boolean;
};

type AuthStateContext = {
  auth: AuthState;
  setAuth: React.Dispatch<SetStateAction<AuthState>>;
};

const initValue: AuthState = {
  access: "",
  refresh: "",
  active: false,
};

const VALUE_KEY = "___auth_tokens";

function getTokens(): AuthState {
  const savedState = localStorage.getItem(VALUE_KEY);
  if (savedState) return JSON.parse(savedState);
  return initValue;
}

const AuthContext = createContext({} as AuthStateContext);

export const AuthProvider = ({ children }: { children?: ReactNode }) => {
  const [auth, setAuth] = useState<AuthState>(getTokens);

  useEffect(() => {
    localStorage.setItem(VALUE_KEY, JSON.stringify(auth));
  }, [auth]);

  return (
    <AuthContext.Provider value={{ auth, setAuth }}>
      {children}
    </AuthContext.Provider>
  );
};

export default AuthContext;
