import { createFileRoute } from "@tanstack/react-router";
import { getUrl } from "../utils";
import google from "../assets/google.svg";

export const Route = createFileRoute("/login")({
  component: RouteComponent,
});

function RouteComponent() {
  return (
    <div className="mt-10 flex justify-center">
      <a href={getUrl()} className="btn border-[#e5e5e5] bg-white text-black">
        <img src={google} alt="" />
        Login with Google
      </a>
    </div>
  );
}
