import { useEffect, useState } from "react";
import useAxiosAuthorized from "../hooks/useAxiosAuthorized";

type UserDetails = {
  name: string;
  email: string;
  picture: string;
};

function User() {
  const axios = useAxiosAuthorized();
  const [user, setUser] = useState<UserDetails>({} as UserDetails);

  useEffect(() => {
    const getData = async () => {
      const r = await axios.get("/me");
      setUser(r.data);
    };

    getData();

    const monitoring = setInterval(async () => {
      getData();
    }, 5000);

    return () => {
      clearInterval(monitoring);
    };
  }, []);

  return (
    <div className="flex items-center gap-4">
      <div className="avatar">
        <div className="w-10 rounded-full">
          <img src={user.picture} />
        </div>
      </div>
      <div className="font-medium dark:text-white">
        <div>{user.name}</div>
        <div className="text-sm text-gray-500 dark:text-gray-400">
          {user.email}
        </div>
      </div>
    </div>
  );
}

export default User;
