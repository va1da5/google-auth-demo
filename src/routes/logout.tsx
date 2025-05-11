import { createFileRoute, Link } from "@tanstack/react-router";

export const Route = createFileRoute("/logout")({
  component: RouteComponent,
});

function RouteComponent() {
  return (
    <div>
      You session has ended. Please go to the{" "}
      <Link className="link" to="/">
        main page
      </Link>{" "}
      or{" "}
      <Link className="link" to="/login">
        login
      </Link>{" "}
      again.
    </div>
  );
}
