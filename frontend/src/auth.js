// ==========================================
// PALLIUM AUTH & VAULT LOGIC (FINAL DEMO VERSION)
// ==========================================

const state = {
    token: null,
    masterKey: null,
    username: null,
    items: [] // Lưu cache danh sách đã giải mã để search cho nhanh
};

// --- 1. CORE CRYPTO (KHÔNG ĐỤNG VÀO) ---
function buffToB64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}
function b64ToBuff(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

async function deriveKeyFromPassword(password, saltString) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: enc.encode(saltString), iterations: 100000, hash: "SHA-256" },
        keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
}

async function encryptBlob(jsonObject) {
    if (!state.masterKey) throw new Error("Mất Master Key!");
    const textData = JSON.stringify(jsonObject);
    const encodedData = new TextEncoder().encode(textData);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv }, state.masterKey, encodedData
    );
    return { iv: buffToB64(iv), data: buffToB64(ciphertext) };
}

async function decryptBlob(ivB64, ciphertextB64) {
    if (!state.masterKey) return null;
    try {
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: b64ToBuff(ivB64) }, state.masterKey, b64ToBuff(ciphertextB64)
        );
        return JSON.parse(new TextDecoder().decode(decrypted));
    } catch (e) { return null; }
}

// --- 2. LOGIC UI & FEATURES ---

// Hàm render lại lưới item (Dùng chung cho Load và Search)
function renderGrid(itemsToRender) {
    const grid = document.getElementById('vault-grid');
    const isRawMode = document.getElementById('toggle-raw').checked;

    grid.innerHTML = '';

    if (itemsToRender.length === 0) {
        grid.innerHTML = `
            <div class="col-span-1 md:col-span-3 flex flex-col items-center justify-center py-20 text-gray-600 opacity-50">
                <div class="text-6xl mb-4">🛡️</div>
                <p class="text-xl font-bold">Your Vault is Locked & Empty</p>
                <p class="text-sm">Add your first secure item to start.</p>
            </div>
        `;
        return;
    }

    itemsToRender.forEach(item => {
        const card = document.createElement('div');
        card.className = "bg-gray-800 p-4 rounded-xl border border-gray-700 hover:border-blue-500 transition shadow-lg relative group";

        let displayUser, displayPassHtml, labelClass;

        if (isRawMode) {
            // --- CHẾ ĐỘ RAW (Show hàng mã hóa) ---
            // Ở chế độ này, show luôn chuỗi mã hóa, không cần ẩn hiện
            displayUser = `<span class="text-yellow-600 break-all text-[10px] font-mono">${item.encrypted_data.substring(0, 50)}...</span>`;
            displayPassHtml = `<span class="text-yellow-600 break-all text-[10px] font-mono">${item.iv}...</span>`;
            labelClass = "text-yellow-500 font-mono";
        } else {
            // --- CHẾ ĐỘ THƯỜNG (Show dữ liệu thật) ---
            displayUser = `<span class="text-gray-200 text-sm font-mono truncate select-all">${item.decrypted.username}</span>`;

            // MẶC ĐỊNH LÀ ẨN (Dùng ID để JS tìm và thay thế text sau)
            // Lưu ý: Không đưa password thật vào attribute nào cả!
            displayPassHtml = `
                <div class="flex items-center justify-between bg-gray-900 rounded px-3 py-2 border border-gray-700 group-hover:border-gray-600 transition">
                    <span id="pass-content-${item.id}" class="text-gray-400 text-lg leading-none font-mono tracking-widest select-none">••••••••</span>
                    <div class="flex gap-2 pl-2 border-l border-gray-700 ml-2">
                        <button onclick="window.togglePass(${item.id}, this)" class="text-gray-500 hover:text-blue-400 transition" title="Show/Hide">
                            👁️
                        </button>
                        <button onclick="window.copyToClip('${item.decrypted.password}', this)" class="text-gray-500 hover:text-green-400 transition" title="Copy Password">
                            📋
                        </button>
                    </div>
                </div>
            `;
            labelClass = "text-blue-400 font-bold";
        }

        card.innerHTML = `
            <div class="flex justify-between items-start mb-4">
                <div class="flex items-center gap-2 overflow-hidden">
                    <span class="text-2xl">${getIcon(item.label)}</span>
                    <h3 class="${labelClass} text-lg truncate" title="${item.label}">
                        ${isRawMode ? '🔒 ' + item.label : item.label}
                    </h3>
                </div>
                ${!isRawMode ? `<button onclick="window.deleteItem(${item.id})" class="text-xs bg-red-500/10 hover:bg-red-500/20 text-red-500 px-2 py-1 rounded transition">🗑️</button>` : ''}
            </div>
            
            <div class="space-y-3">
                <div class="bg-gray-900/50 p-2 rounded border border-gray-800">
                    <p class="text-[10px] uppercase text-gray-500 font-bold mb-1">Username / ID</p>
                    ${displayUser}
                </div>

                <div>
                    <p class="text-[10px] uppercase text-gray-500 font-bold mb-1">Password</p>
                    ${displayPassHtml}
                </div>
            </div>
        `;
        grid.appendChild(card);
    });
}

function getIcon(label) {
    const l = label.toLowerCase();
    if (l.includes('facebook')) return '📘';
    if (l.includes('google') || l.includes('gmail')) return '🔴';
    if (l.includes('bank') || l.includes('vietcombank')) return '🏦';
    if (l.includes('github')) return '🐱';
    if (l.includes('game') || l.includes('steam')) return '🎮';
    return '🔑';
}

window.togglePass = (id, btn) => {
    const span = document.getElementById(`pass-content-${id}`);
    const item = state.items.find(i => i.id === id);

    if (!item || !span) return;

    // Kiểm tra trạng thái hiện tại dựa vào nội dung text
    if (span.textContent.includes("•••")) {
        // Đang ẩn -> Hiện (Lấy từ RAM ra nhét vào DOM)
        span.textContent = item.decrypted.password;
        span.classList.remove("tracking-widest", "text-lg");
        span.classList.add("text-sm", "text-white");
        btn.textContent = "🙈"; // Đổi icon thành che
    } else {
        // Đang hiện -> Ẩn (Xóa khỏi DOM)
        span.textContent = "••••••••";
        span.classList.add("tracking-widest", "text-lg");
        span.classList.remove("text-sm", "text-white");
        btn.textContent = "👁️"; // Đổi icon thành xem
    }
};

window.copyToClip = (text, btn) => {
    navigator.clipboard.writeText(text);
    // Hiệu ứng copy nhỏ gọn hơn
    const originalIcon = btn.textContent;
    btn.textContent = "✅";
    setTimeout(() => {
        btn.textContent = originalIcon;
    }, 1000);
};

// Tải dữ liệu từ API
async function loadVaultItems() {
    const grid = document.getElementById('vault-grid');
    grid.innerHTML = '<div class="col-span-3 text-center text-blue-400 animate-pulse mt-10">⏳ Đang giải mã dữ liệu an toàn...</div>';

    try {
        const res = await fetch('http://127.0.0.1:8000/api/v1/vault/', {
            headers: { 'Authorization': `Bearer ${state.token}` }
        });
        if (!res.ok) throw new Error("Lỗi tải danh sách");

        const rawItems = await res.json();
        state.items = [];

        for (const item of rawItems) {
            const secret = await decryptBlob(item.iv, item.encrypted_data);
            if (secret) state.items.push({ ...item, decrypted: secret });
        }

        renderGrid(state.items); // Render lần đầu

    } catch (err) {
        grid.innerHTML = `<p class="text-red-500 text-center col-span-3">Lỗi: ${err.message}</p>`;
    }
}

// --- 3. EXPORT FUNCTIONS ---
window.copyToClip = (text, btn) => {
    navigator.clipboard.writeText(text);
    const originalText = btn.textContent;
    btn.textContent = "Copied!";
    btn.classList.add("text-green-400");
    setTimeout(() => {
        btn.textContent = originalText;
        btn.classList.remove("text-green-400");
    }, 1500);
};

window.deleteItem = async (id) => {
    if(!confirm("Xóa mục này vĩnh viễn?")) return;
    try {
        const res = await fetch(`http://127.0.0.1:8000/api/v1/vault/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${state.token}` }
        });
        if(res.ok) loadVaultItems();
    } catch(e) { console.error(e); }
};

// --- 4. INIT APP ---
export function initAuth() {
    console.log("🔥 Pallium Core Ready");

    // LOGIN EVENT
    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        const user = document.getElementById('username').value;
        const pass = document.getElementById('password').value;

        try {
            const formData = new URLSearchParams();
            formData.append('username', user);
            formData.append('password', pass);

            const response = await fetch('http://127.0.0.1:8000/api/v1/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: formData
            });

            if (!response.ok) throw new Error("Đăng nhập thất bại");

            const data = await response.json();
            state.token = data.access_token;
            state.username = user;
            state.masterKey = await deriveKeyFromPassword(pass, user);

            document.getElementById('login-screen').classList.add('hidden-screen');
            document.getElementById('vault-screen').classList.remove('hidden-screen');
            document.getElementById('user-display').textContent = user;

            loadVaultItems();

        } catch (err) {
            const errDiv = document.getElementById('login-error');
            errDiv.textContent = err.message;
            errDiv.classList.remove('hidden');
        }
    });

    // LOGOUT EVENT (MỚI)
    document.getElementById('logout-btn').addEventListener('click', () => {
        state.token = null;
        state.masterKey = null;
        state.username = null;
        state.items = [];

        document.getElementById('vault-screen').classList.add('hidden-screen');
        document.getElementById('login-screen').classList.remove('hidden-screen');
        document.getElementById('login-form').reset();
        document.getElementById('password').value = ""; // Xóa pass cho chắc
        console.log("🔒 Logged out & RAM cleared.");
    });

    // TOGGLE RAW DATA EVENT (MỚI)
    document.getElementById('toggle-raw').addEventListener('change', () => {
        renderGrid(state.items); // Vẽ lại grid dựa trên trạng thái checkbox
    });

    // SEARCH EVENT
    document.getElementById('search-input').addEventListener('input', (e) => {
        const keyword = e.target.value.toLowerCase();
        const filtered = state.items.filter(item =>
            item.label.toLowerCase().includes(keyword) ||
            item.decrypted.username.toLowerCase().includes(keyword)
        );
        renderGrid(filtered);
    });

    // MODAL & SAVE (Giữ nguyên logic cũ)
    const addModal = document.getElementById('add-modal');
    document.getElementById('add-item-btn').onclick = () => addModal.classList.remove('hidden-screen');
    document.getElementById('cancel-add-btn').onclick = () => addModal.classList.add('hidden-screen');

    document.getElementById('save-item-btn').addEventListener('click', async () => {
        try {
            const secretData = {
                username: document.getElementById('item-username').value,
                password: document.getElementById('item-password').value,
                risk_level: parseInt(document.getElementById('item-risk').value)
            };

            const encryptedResult = await encryptBlob(secretData);
            const payload = {
                label: document.getElementById('item-label').value,
                encrypted_data: encryptedResult.data,
                iv: encryptedResult.iv
            };

            const response = await fetch('http://127.0.0.1:8000/api/v1/vault/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${state.token}`
                },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                alert("✅ Đã lưu!");
                addModal.classList.add('hidden-screen');
                document.getElementById('add-form').reset();
                loadVaultItems();
            } else {
                alert("❌ Lỗi lưu dữ liệu");
            }
        } catch (error) {
            console.error(error);
            alert("❌ Lỗi Client: " + error.message);
        }
    });
}