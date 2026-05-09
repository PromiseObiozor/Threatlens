import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:8000/api",
});

export const scanEmail = (payload) => api.post("/scan",  payload).then(r => r.data);