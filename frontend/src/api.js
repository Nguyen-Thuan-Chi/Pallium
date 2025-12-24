import { API_URL } from "./config.js";

// Hàm lấy token từ bộ nhớ (biến tạm) hoặc sessionStorage
// Lưu ý: Đồ án này ta ưu tiên lưu biến tạm để demo tính năng "mất khi reload" của Level 3
// Nhưng để tiện login, ta lưu token vào sessionStorage
export function getToken() {
    return sessionStorage.getItem("access_token");
}

export async function request(endpoint, method = "GET", body = null) {
    const headers = {
        "Content-Type": "application/json",
    };

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

        // Xử lý lỗi 401 (Hết phiên đăng nhập)
        if (response.status === 401) {
            alert("Phiên đăng nhập hết hạn. Vui lòng đăng nhập lại.");
            sessionStorage.removeItem("access_token");
            window.location.reload();
            return null;
        }

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.detail || "Có lỗi xảy ra");
        }
        return data;
    } catch (error) {
        console.error("API Error:", error);
        throw error;
    }
}