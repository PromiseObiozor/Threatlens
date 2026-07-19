import axios from "axios";

export const TOKEN_STORAGE_KEY = "threatlens_token";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000",
});

export const registerUser = (payload) =>
  api.post("/register", payload).then((response) => response.data);

export const loginUser = (payload) =>
  api.post("/login", payload).then((response) => response.data);

export const scanEmail = (payload, token) =>
  api
    .post("/scan", payload, {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
    .then((response) => response.data);

export const getHistory = (token) =>
  api
    .get("/history", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    })
    .then((response) => response.data);

export const deleteHistoryItem = (scanId, token) =>
  api.delete(`/history/${scanId}`, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
