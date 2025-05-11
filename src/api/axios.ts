import axios from "axios";

const BASE_URL = new URL(import.meta.env.VITE_BACKEND_URI);

export default axios.create({
  baseURL: BASE_URL.toString(),
});

export const axiosAuthorized = axios.create({
  baseURL: BASE_URL.toString(),
  headers: { "Content-Type": "application/json" },
  withCredentials: true,
});
