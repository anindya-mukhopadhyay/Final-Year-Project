/**
 * AnswerChain Enterprise Client SDK & Shared Helpers
 */

const API_BASE = (window.location.port === "8000" || window.location.port === "5500")
    ? "http://127.0.0.1:8000"
    : `${window.location.protocol}//${window.location.hostname}:8000`;

function getApiBase() {
    return API_BASE;
}

function getToken() {
    return localStorage.getItem("answerchain_token") || "";
}

function getCurrentUser() {
    try {
        const raw = localStorage.getItem("answerchain_user");
        return raw ? JSON.parse(raw) : null;
    } catch (e) {
        return null;
    }
}

function setSession(token, user) {
    localStorage.setItem("answerchain_token", token);
    localStorage.setItem("answerchain_user", JSON.stringify(user));
}

function clearSession() {
    localStorage.removeItem("answerchain_token");
    localStorage.removeItem("answerchain_user");
}

async function authFetch(endpoint, options = {}) {
    const token = getToken();
    const headers = options.headers || {};

    if (token && !headers["Authorization"]) {
        headers["Authorization"] = `Bearer ${token}`;
    }

    if (!headers["Content-Type"] && !(options.body instanceof FormData)) {
        headers["Content-Type"] = "application/json";
    }

    const url = endpoint.startsWith("http") ? endpoint : `${API_BASE}${endpoint}`;
    const response = await fetch(url, { ...options, headers });

    if (response.status === 401) {
        clearSession();
        // Redirect to login if on protected page
        if (!window.location.pathname.includes("login.html") && !window.location.pathname.includes("/verify/")) {
            window.location.href = "/login.html";
        }
    }

    let data;
    try {
        data = await response.json();
    } catch (e) {
        data = { error: "Non-JSON response", status: response.status };
    }

    return {
        ok: response.ok,
        status: response.status,
        data,
    };
}

function requireAuth(allowedRoles = []) {
    const user = getCurrentUser();
    const token = getToken();

    if (!user || !token) {
        window.location.href = "/login.html";
        return null;
    }

    if (allowedRoles.length > 0) {
        const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];
        if (!roles.includes(user.role) && user.role !== "ADMIN") {
            alert(`Access Denied: Your role (${user.role}) does not have permission to view this section.`);
            // Redirect to appropriate home
            redirectToRoleHome(user.role);
            return null;
        }
    }

    return user;
}

function redirectToRoleHome(role) {
    switch (role) {
        case "UNIVERSITY":
            window.location.href = "/university/dashboard.html";
            break;
        case "TEACHER":
            window.location.href = "/teacher/dashboard.html";
            break;
        case "AUTHORITY":
            window.location.href = "/authority/dashboard.html";
            break;
        case "ADMIN":
            window.location.href = "/admin/dashboard.html";
            break;
        case "VERIFIER":
            window.location.href = "/verify/index.html";
            break;
        default:
            window.location.href = "/login.html";
    }
}

async function logoutUser() {
    try {
        await authFetch("/api/auth/logout", { method: "POST" });
    } catch (e) {
        console.warn("Logout error:", e);
    }
    clearSession();
    window.location.href = "/login.html";
}

function showToast(message, type = "info") {
    let container = document.getElementById("toast-container");
    if (!container) {
        container = document.createElement("div");
        container.id = "toast-container";
        container.style.cssText = `
            position: fixed;
            bottom: 24px;
            right: 24px;
            z-index: 99999;
            display: flex;
            flex-direction: column;
            gap: 10px;
        `;
        document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    const bgColors = {
        success: "#159567",
        error: "#e53e3e",
        warning: "#e98b2a",
        info: "#315efb",
    };

    toast.style.cssText = `
        background: ${bgColors[type] || "#172033"};
        color: white;
        padding: 12px 20px;
        border-radius: 8px;
        font-size: 14px;
        font-weight: 500;
        box-shadow: 0 4px 14px rgba(0,0,0,0.18);
        display: flex;
        align-items: center;
        gap: 10px;
        transition: all 0.3s ease;
        opacity: 0;
        transform: translateY(10px);
    `;
    toast.textContent = message;

    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = "1";
        toast.style.transform = "translateY(0)";
    }, 10);

    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateY(10px)";
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}
