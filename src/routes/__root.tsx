import { createRootRoute, Link, Outlet } from "@tanstack/react-router";
import User from "../components/User";
import useAuth from "../hooks/useAuth";

export const Route = createRootRoute({
  component: Root,
});

function Root() {
  const { auth } = useAuth();
  return (
    <>
      <div className="container mx-auto mt-5">
        <div className="mb-20 flex justify-between">
          <div>
            <h2 className="text-3xl font-bold">Google Auth DEMO</h2>
          </div>
          <div className="self-center">
            {auth.active && <User />}
            {!auth.active && <Link to="/login">Login</Link>}
          </div>
        </div>
        <div className="flex justify-center">
          <Outlet />
        </div>
      </div>
    </>
  );
}
