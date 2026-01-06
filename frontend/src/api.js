import { API_URL } from "./config.js";

export function getToken() {
    return sessionStorage.getItem("access_token");
}

export async function request(endpoint, method = "GET", body = null) {
    const headers = {
        "Content-Type": "application/json",
    };

    // Note: Project này đang dùng token lưu trong RAM (biến state ở auth.js)
    // Nếu bạn muốn dùng hàm này, bạn cần truyền token vào hoặc lưu token vào sessionStorage lúc login
    const token = getToken();
    if (token) {
        headers["Authorization"] = `Bearer ${token}`;
    }

    const config = {
        method,
        headers,
    };

    if (body) {
        config.body = JSON.stringify(body);
    }

    try {
        const response = await fetch(`${API_URL}${endpoint}`, config);

        if (response.status === 401) {
            console.warn("Unauthorized access");
            // window.location.reload(); // Uncomment nếu muốn force reload
        }

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.detail || "API Error");
        }
        return data;
    } catch (error) {
        console.error("Fetch Error:", error);
        throw error;
    }
}
export { request as apiRequest };
