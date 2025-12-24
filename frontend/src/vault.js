import { request } from "./api.js";
import { decryptData, encryptData } from "./crypto.js";
import { appState } from "./state.js";

const grid = document.getElementById("vault-grid");

// --- KHỞI TẠO EVENT LISTENERS ---
export function initVaultListeners() {
    console.log("Initializing Vault Listeners...");

    const addBtn = document.getElementById("add-item-btn");
    const addModal = document.getElementById("add-modal");
    const cancelBtn = document.getElementById("cancel-add-btn");
    const addForm = document.getElementById("add-form");

    // NÚT MỚI
    const saveBtn = document.getElementById("save-item-btn");

    if (!addBtn || !addModal || !addForm || !saveBtn) {
        console.error("❌ ERROR: Thiếu ID trong HTML (Kiểm tra save-item-btn)");
        return;
    }

    addBtn.onclick = () => {
        addModal.classList.remove("hidden-screen");
        addModal.style.display = "flex";
    };

    cancelBtn.onclick = () => {
        addModal.style.display = "none";
        addForm.reset();
    };

    // --- [LOGIC MỚI] BẮT SỰ KIỆN CLICK TRỰC TIẾP ---
    saveBtn.onclick = async () => {
        console.log("🖱️ Save Button Clicked!"); // Log để kiểm chứng
        await handleCreateItem(addForm, addModal, saveBtn);
    };

    console.log("✅ Vault Listeners Ready");
}

async function handleCreateItem(form, modal, btn) {
    const originalText = btn.innerText;

    try {
        // CHECK KEY TRƯỚC KHI LÀM BẤT CỨ ĐIỀU GÌ
        if (!appState.masterKey) {
            alert("❌ LỖI: Mất chìa khóa (Key is null). Vui lòng F5 và đăng nhập lại.");
            return;
        }

        btn.innerText = "Encrypting...";
        btn.disabled = true;

        // Lấy dữ liệu
        const labelInput = document.getElementById("item-label");
        const usernameInput = document.getElementById("item-username");
        const passwordInput = document.getElementById("item-password");

        // Validate thủ công (vì ta bỏ type=submit nên phải tự check rỗng)
        if(!labelInput.value || !usernameInput.value || !passwordInput.value) {
            alert("Vui lòng điền đầy đủ thông tin!");
            btn.innerText = originalText;
            btn.disabled = false;
            return;
        }

        const label = labelInput.value;
        const risk_level = parseInt(document.getElementById("item-risk").value);

        const secretPayload = {
            username: usernameInput.value,
            password: passwordInput.value,
            created_at: Date.now()
        };

        console.log("🔒 Encrypting payload...");
        const { encrypted_data, iv } = await encryptData(secretPayload, appState.masterKey);

        const payload = {
            label: label,
            risk_level: risk_level,
            encrypted_data: encrypted_data,
            iv: iv,
            auth_tag: ""
        };

        console.log("📤 Sending:", payload);
        await request("/vault/", "POST", payload);

        modal.style.display = "none";
        form.reset();
        loadVaultItems();

        // Thông báo nhỏ gọn thay vì Alert phiền phức
        console.log("Saved Successfully!");

    } catch (err) {
        console.error("Save Error:", err);
        alert("Lỗi: " + err.message);
    } finally {
        btn.innerText = originalText;
        btn.disabled = false;
    }
}

// --- LOGIC TẢI DANH SÁCH VAULT ---
export async function loadVaultItems() {
    grid.innerHTML = '<p class="text-gray-400 animate-pulse">Loading vault...</p>';
    
    try {
        const items = await request("/vault/");
        grid.innerHTML = "";
        
        if (items.length === 0) {
            grid.innerHTML = '<p class="text-gray-500 italic">Vault is empty.</p>';
            return;
        }

        const key = appState.masterKey;

        for (const item of items) {
            try {
                // Giải mã
                const decryptedObj = await decryptData(item.encrypted_data, item.iv, key);
                renderItem(item, decryptedObj);
            } catch (e) {
                console.error(`Failed item ${item.id}`, e);
                renderErrorItem(item);
            }
        }
    } catch (err) {
        console.error(err);
        grid.innerHTML = '<p class="text-red-500">Failed to load vault.</p>';
    }
}

// --- RENDER GIAO DIỆN ---
function renderItem(meta, data) {
    const card = document.createElement("div");
    card.className = "bg-gray-800 p-4 rounded border border-gray-700 hover:border-blue-500 transition shadow-lg group relative";
    
    let riskBadge = "";
    if (meta.risk_level === 1) riskBadge = '<span class="text-xs bg-green-900 text-green-300 px-2 py-1 rounded font-bold">LOW</span>';
    if (meta.risk_level === 2) riskBadge = '<span class="text-xs bg-yellow-900 text-yellow-300 px-2 py-1 rounded font-bold">MED</span>';
    if (meta.risk_level === 3) riskBadge = '<span class="text-xs bg-red-900 text-red-300 px-2 py-1 rounded font-bold">HIGH</span>';

    card.innerHTML = `
        <div class="flex justify-between items-start mb-3">
            <h3 class="font-bold text-lg text-white truncate w-3/4">${meta.label}</h3>
            ${riskBadge}
        </div>
        
        <div class="space-y-2">
            <div>
                <p class="text-xs text-gray-500 uppercase">Username</p>
                <p class="text-gray-300 text-sm font-mono bg-gray-900 p-1 rounded select-all">${data.username}</p>
            </div>
            <div>
                <p class="text-xs text-gray-500 uppercase">Password</p>
                <div class="flex justify-between bg-gray-900 p-1 rounded cursor-pointer hover:bg-gray-700 transition" onclick="navigator.clipboard.writeText('${data.password}')">
                    <p class="text-blue-400 text-sm font-mono filter blur-sm group-hover:blur-none transition duration-200 select-all">
                        ${data.password}
                    </p>
                    <span class="text-xs text-gray-500 self-center">COPY</span>
                </div>
            </div>
        </div>
        
        <button onclick="window.deleteItem(${meta.id})" class="absolute top-2 right-2 text-gray-600 hover:text-red-500 opacity-0 group-hover:opacity-100 transition">
            ✖
        </button>
    `;
    grid.appendChild(card);
}

function renderErrorItem(meta) {
    const card = document.createElement("div");
    card.className = "bg-gray-800 p-4 rounded border border-red-900 opacity-60";
    card.innerHTML = `
        <h3 class="font-bold text-gray-500">${meta.label || 'Unknown'}</h3>
        <p class="text-red-500 text-xs mt-2">Decryption failed (Wrong Key?)</p>
    `;
    grid.appendChild(card);
}

// Gắn hàm xóa vào window để HTML gọi được
window.deleteItem = async (id) => {
    if(!confirm("Delete this item?")) return;
    await request(`/vault/${id}`, "DELETE");
    loadVaultItems();
};