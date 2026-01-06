// ==========================================
// PALLIUM AUTH & VAULT LOGIC (FINAL - FIXED)
// ==========================================
import { API_URL } from './config.js';
import {
    generateSeedPhrase,
    setupSeedRecovery
} from './seed.js';


const state = {
    token: null,
    masterKey: null,
    username: null,
    items: [] // Cache danh sách vault
};

// --- 1. CORE CRYPTO (CLIENT-SIDE) ---

/**
 * Convert ArrayBuffer/Uint8Array to Base64 string
 * Uses a chunked approach to avoid stack overflow on large buffers
 * @param {ArrayBuffer|Uint8Array} buffer
 * @returns {string} Base64 encoded string
 */
function buffToB64(buffer) {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    const len = bytes.byteLength;

    // Build binary string using loop (safe for any buffer size)
    let binary = '';
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    return btoa(binary);
}

/**
 * Convert Base64 string to Uint8Array
 * @param {string} b64 - Base64 encoded string
 * @returns {Uint8Array}
 */
function b64ToBuff(b64) {
    const binaryString = atob(b64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);

    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }

    return bytes;
}

/**
 * Generate cryptographically secure random salt (16 bytes = 128 bits)
 * @returns {string} Base64 encoded salt
 */
function generateRandomSalt() {
    const array = new Uint8Array(16);
    window.crypto.getRandomValues(array);
    return buffToB64(array);
}

/**
 * Generate a strong random password
 * @param {number} length - Password length (default: 24)
 * @returns {string} Generated password
 */
function generateStrongPassword(length = 24) {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
    let password = "";
    const values = new Uint8Array(length);
    window.crypto.getRandomValues(values);
    for (let i = 0; i < length; i++) {
        password += charset[values[i] % charset.length];
    }
    return password;
}

/**
 * Derive Master Key from password using PBKDF2
 * @param {string} password - User's master password
 * @param {string} saltString - Base64 encoded salt
 * @returns {Promise<CryptoKey>} Derived AES-GCM key
 */
async function deriveKeyFromPassword(password, saltString) {
    const enc = new TextEncoder();

    // Import password as raw key material for PBKDF2
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,  // not extractable (this is just key material)
        ["deriveKey"]
    );

    // Derive AES-GCM key using PBKDF2
    // CRITICAL: extractable must be TRUE to allow exportKey for AuthKey derivation
    // NOTE: keyUsages should only contain valid AES-GCM usages (encrypt/decrypt)
    //       "exportKey" is NOT a valid usage - extractable:true is what allows export
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: enc.encode(saltString),
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,   // extractable: MUST be true to create AuthKey
        ["encrypt", "decrypt"]  // Valid AES-GCM usages only
    );
}

/**
 * Derive Auth Key from Master Key (Hash-of-Key architecture)
 * This is what gets sent to the server - NOT the password or master key
 * @param {CryptoKey} masterKey - The derived master key
 * @returns {Promise<string>} Base64 encoded SHA-256 hash of the master key
 */
async function deriveAuthKey(masterKey) {
    // Export the raw key bytes
    const rawKey = await window.crypto.subtle.exportKey("raw", masterKey);

    // Hash the raw key with SHA-256
    const hashBuffer = await window.crypto.subtle.digest("SHA-256", rawKey);

    // Return as Base64 string for transmission
    return buffToB64(hashBuffer);
}

/**
 * Encrypt a JSON object using AES-GCM with the Master Key
 * @param {Object} jsonObject - Object to encrypt
 * @returns {Promise<{iv: string, data: string}>} Encrypted blob with IV
 */
async function encryptBlob(jsonObject) {
    if (!state.masterKey) {
        throw new Error("Critical: Master Key not loaded.");
    }

    const textData = JSON.stringify(jsonObject);
    const encodedData = new TextEncoder().encode(textData);

    // Generate random 96-bit IV (recommended for AES-GCM)
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        state.masterKey,
        encodedData
    );

    return {
        iv: buffToB64(iv),
        data: buffToB64(ciphertext)
    };
}

/**
 * Decrypt an encrypted blob using AES-GCM with the Master Key
 * @param {string} ivB64 - Base64 encoded IV
 * @param {string} ciphertextB64 - Base64 encoded ciphertext
 * @returns {Promise<Object|null>} Decrypted object or null if decryption fails
 */
async function decryptBlob(ivB64, ciphertextB64) {
    if (!state.masterKey) {
        return null;
    }

    try {
        const iv = b64ToBuff(ivB64);
        const ciphertext = b64ToBuff(ciphertextB64);

        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            state.masterKey,
            ciphertext
        );

        const decoded = new TextDecoder().decode(decrypted);
        return JSON.parse(decoded);
    } catch (e) {
        // Decryption failed (wrong key, corrupted data, or duress mode)
        // Return null so UI can render "Locked" state
        console.warn("Decryption failed:", e.message);
        return null;
    }
}

// --- 2. RENDER UI FUNCTIONS ---

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
        let riskConfig = { border: "border-green-500/40 hover:border-green-400", badge: "LOW RISK" };
        if (item.risk_level === 2) riskConfig = { border: "border-yellow-500/40 hover:border-yellow-400", badge: "MEDIUM" };
        if (item.risk_level === 3) riskConfig = { border: "border-red-500/40 hover:border-red-400", badge: "HIGH RISK" };

        const card = document.createElement('div');
        card.className = `bg-gray-800 p-4 rounded-xl border ${riskConfig.border} transition shadow-lg relative group`;

        let displayUser, displayPassHtml, labelDisplay;

        if (isRawMode) {
            displayUser = `<span class="text-yellow-600 break-all text-[10px] font-mono">${item.encrypted_data.substring(0, 50)}...</span>`;
            displayPassHtml = `<span class="text-yellow-600 break-all text-[10px] font-mono">${item.iv}...</span>`;
            labelDisplay = `🔒 ${item.label}`;
        } else {
            if (item.decrypted) {
                displayUser = `<span class="text-gray-200 text-sm font-mono truncate select-all">${item.decrypted.username}</span>`;
                displayPassHtml = `
                    <div class="flex items-center justify-between bg-gray-900 rounded px-3 py-2 border border-gray-700 group-hover:border-gray-600 transition">
                        <span id="pass-content-${item.id}" class="text-gray-400 text-lg leading-none font-mono tracking-widest select-none">••••••••</span>
                        <div class="flex gap-2 pl-2 border-l border-gray-700 ml-2">
                            <button onclick="window.togglePass(${item.id}, this)" class="text-gray-500 hover:text-blue-400 transition">👁️</button>
                            <button onclick="window.copyToClip('${item.decrypted.password}', this)" class="text-gray-500 hover:text-green-400 transition">📋</button>
                        </div>
                    </div>
                `;
                labelDisplay = item.label;
            } else {
                displayUser = `<span class="text-red-500 text-xs italic">Locked (Duress Mode)</span>`;
                displayPassHtml = `<span class="text-red-500 text-xs italic">Access Denied</span>`;
                labelDisplay = `🚫 ${item.label}`;
            }
        }

        card.innerHTML = `
            <div class="flex justify-between items-start mb-4">
                <div class="flex items-center gap-3 overflow-hidden w-full">
                    <span class="text-3xl">${getIcon(item.label)}</span>
                    <div class="flex flex-col overflow-hidden">
                        <h3 class="text-blue-400 font-bold text-lg truncate leading-tight" title="${item.label}">${labelDisplay}</h3>
                        <div class="mt-1"><span class="text-[9px] font-bold text-gray-400 bg-gray-700 px-1.5 py-0.5 rounded border border-gray-600 tracking-wider">${riskConfig.badge}</span></div>
                    </div>
                </div>
                ${(!isRawMode && item.decrypted) ? `<button onclick="window.deleteItem(${item.id})" class="text-xs bg-red-500/10 hover:bg-red-500/20 text-red-500 px-2 py-1.5 rounded transition shrink-0 ml-2">🗑️</button>` : ''}
            </div>
            <div class="space-y-3">
                <div class="bg-gray-900/50 p-2 rounded border border-gray-800">
                    <p class="text-[10px] uppercase text-gray-500 font-bold mb-1">Username</p>
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
    if (l.includes('face')) return '📘';
    if (l.includes('goo') || l.includes('gmail')) return '🔴';
    if (l.includes('bank') || l.includes('viet')) return '🏦';
    if (l.includes('git')) return '🐱';
    if (l.includes('game') || l.includes('steam')) return '🎮';
    return '🔑';
}

// --- 3. API CALLS (Data Fetching) ---

async function loadVaultItems() {
    try {
        const res = await fetch(`${API_URL}/api/v1/vault/`, {
            headers: { 'Authorization': `Bearer ${state.token}` }
        });
        if (!res.ok) throw new Error("Failed to load vault items");

        const rawItems = await res.json();
        state.items = [];

        for (const item of rawItems) {
            try {
                const secret = await decryptBlob(item.iv, item.encrypted_data);
                if (secret) {
                    state.items.push({ ...item, decrypted: secret });
                } else {
                    state.items.push({ ...item, decrypted: null });
                }
            } catch (e) {
                console.warn("Decrypt error for item:", item.id, e);
                state.items.push({ ...item, decrypted: null });
            }
        }
        renderGrid(state.items);
    } catch (err) {
        console.error("Failed to load vault items:", err);
    }
}

// --- 4. EXPORTED HELPERS ---

window.togglePass = (id, btn) => {
    const span = document.getElementById(`pass-content-${id}`);
    const item = state.items.find(i => i.id === id);
    if (!item || !span || !item.decrypted) return;

    if (span.textContent.includes("•••")) {
        span.textContent = item.decrypted.password;
        span.classList.remove("tracking-widest", "text-lg");
        span.classList.add("text-sm", "text-white");
        btn.textContent = "🙈";
    } else {
        span.textContent = "••••••••";
        span.classList.add("tracking-widest", "text-lg");
        span.classList.remove("text-sm", "text-white");
        btn.textContent = "👁️";
    }
};

window.copyToClip = (text, btn) => {
    navigator.clipboard.writeText(text);
    const originalText = btn.textContent;
    btn.textContent = "✅";
    setTimeout(() => btn.textContent = originalText, 1000);
};

window.deleteItem = async (id) => {
    if (!confirm("Are you sure? This cannot be undone.")) return;
    try {
        const res = await fetch(`${API_URL}/api/v1/vault/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': `Bearer ${state.token}` }
        });
        if (res.ok) {
            loadVaultItems();
        } else {
            alert("Failed to delete item.");
        }
    } catch (e) {
        console.error("Delete failed:", e);
    }
};

// --- 5. INITIALIZATION ---

export function initAuth() {
    console.log("🔥 Pallium Core Ready - Zero-Knowledge Mode");

    const loginScreen = document.getElementById('login-screen');
    const registerScreen = document.getElementById('register-screen');
    const vaultScreen = document.getElementById('vault-screen');

    // Navigation
    document.getElementById('go-to-register').onclick = () => {
        loginScreen.classList.add('hidden-screen');
        registerScreen.classList.remove('hidden-screen');
    };
    document.getElementById('go-to-login').onclick = () => {
        registerScreen.classList.add('hidden-screen');
        loginScreen.classList.remove('hidden-screen');
    };

    // Modal Events
    const addModal = document.getElementById('add-modal');
    document.getElementById('add-item-btn').onclick = () => addModal.classList.remove('hidden-screen');
    document.getElementById('cancel-add-btn').onclick = () => addModal.classList.add('hidden-screen');

    // --- GENERATOR BUTTON HANDLER ---
    const passInput = document.getElementById('item-password');
    const genBtn = document.getElementById('btn-gen-pass');

    if (genBtn && passInput) {
        genBtn.addEventListener('click', () => {
            const newPass = generateStrongPassword(24);
            passInput.value = newPass;
            passInput.type = 'text'; // Show password so user can see it

            const originalIcon = genBtn.textContent;
            genBtn.textContent = "✅";
            setTimeout(() => {
                genBtn.textContent = originalIcon;
                // passInput.type = 'password'; // Uncomment to auto-hide
            }, 1500);
        });
    }

    // --- REGISTER LOGIC ---
    document.getElementById('register-form').addEventListener('submit', async (e) => {
        e.preventDefault();

        const user = document.getElementById('reg-username').value.trim();
        const pass = document.getElementById('reg-password').value;
        const confirmPassword = document.getElementById('reg-confirm-password').value;
        const errDiv = document.getElementById('register-error');

        // Validate password match
        if (pass !== confirm) {
            errDiv.textContent = "Passwords do not match!";
            errDiv.classList.remove('hidden');
            return;
        }

        // Validate password strength (minimum 8 characters)
        if (pass.length < 8) {
            errDiv.textContent = "Password must be at least 8 characters!";
            errDiv.classList.remove('hidden');
            return;
        }

        // Generate seed phrase for recovery (client-side only)
        let seedPhrase = generateSeedPhrase(12);

        // Create and force download the seed phrase file
        const fileContent = `========================================
PALLIUM SEED PHRASE - KEEP THIS SAFE!
========================================

⚠️ WARNING: This is your ONLY backup for account recovery.
Anyone with this phrase can reset your password.
Store it securely offline. Never share it with anyone.

YOUR SEED PHRASE (12 words):
${seedPhrase}

========================================
This seed phrase is shown ONLY ONCE.
Pallium does NOT store your seed phrase.
If you lose it, you CANNOT recover your account.
========================================
`;

        const blob = new Blob([fileContent], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const downloadLink = document.createElement('a');
        downloadLink.href = url;
        downloadLink.download = 'pallium-seed.txt';

        // Force download - this triggers the browser's download mechanism
        document.body.appendChild(downloadLink);
        downloadLink.click();
        document.body.removeChild(downloadLink);
        URL.revokeObjectURL(url);

        // Confirm download before proceeding
        const confirmDownload = window.confirm(
            "⚠️ IMPORTANT: Your seed phrase file has been downloaded.\n\n" +
            "Please verify you have saved 'pallium-seed.txt' before continuing.\n\n" +
            "This is your ONLY chance to save your recovery phrase.\n\n" +
            "Click OK to continue with registration, or Cancel to abort."
        );

        if (!confirmDownload) {
            // User cancelled - clear seed and abort
            seedPhrase = null;
            errDiv.textContent = "Registration cancelled. Please try again and save your seed phrase.";
            errDiv.classList.remove('hidden');
            errDiv.classList.remove('bg-blue-900/30', 'border-blue-900', 'text-blue-400');
            errDiv.classList.add('bg-red-900/30', 'border-red-900', 'text-red-400');
            return;
        }

        try {
            errDiv.textContent = "Creating secure vault...";
            errDiv.classList.remove('hidden');
            errDiv.classList.remove('bg-red-900/30', 'border-red-900', 'text-red-400');
            errDiv.classList.add('bg-blue-900/30', 'border-blue-900', 'text-blue-400');

            // STEP 1: Generate client-side salt
            const salt = generateRandomSalt();

            // STEP 2: Derive Master Key from password + salt
            const tempMasterKey = await deriveKeyFromPassword(pass, salt);

            // STEP 3: Derive Auth Key (Hash of Master Key)
            const authKey = await deriveAuthKey(tempMasterKey);

            // STEP 4: Send to server (password is the authKey, not raw password!)
            const res = await fetch(`${API_URL}/api/v1/auth/register`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username: user,
                    password: authKey,  // AuthKey, NOT raw password
                    kdf_salt: salt
                })
            });

            if (!res.ok) {
                const data = await res.json();
                throw new Error(data.detail || "Registration failed");
            }

            // STEP 5: Auto-login to set up seed recovery
            state.masterKey = tempMasterKey;

            const formData = new URLSearchParams();
            formData.append('username', user);
            formData.append('password', authKey);

            const loginRes = await fetch(`${API_URL}/api/v1/auth/login`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: formData
            });

            if (loginRes.ok) {
                const loginData = await loginRes.json();
                state.token = loginData.access_token;

                // STEP 6: Set up seed recovery on server (sends verifier, NOT seed)
                errDiv.textContent = "Setting up recovery...";
                await setupSeedRecovery(seedPhrase);

                // STEP 7: Clear token after setup (user will log in manually)
                state.token = null;
                state.masterKey = null;
            }

            // Clear seed phrase from memory immediately
            seedPhrase = null;

            alert("✅ Registration Successful! Your seed phrase has been saved.\nPlease Log In.");
            document.getElementById('register-form').reset();
            registerScreen.classList.add('hidden-screen');
            loginScreen.classList.remove('hidden-screen');
            document.getElementById('username').value = user;
            errDiv.classList.add('hidden');

        } catch (err) {
            // Clear seed phrase on error
            seedPhrase = null;
            state.token = null;
            state.masterKey = null;

            errDiv.textContent = err.message;
            errDiv.classList.remove('hidden');
            errDiv.classList.remove('bg-blue-900/30', 'border-blue-900', 'text-blue-400');
            errDiv.classList.add('bg-red-900/30', 'border-red-900', 'text-red-400');
        }
    });

    // --- LOGIN LOGIC ---
    document.getElementById('login-form').addEventListener('submit', async (e) => {
        e.preventDefault();

        const user = document.getElementById('username').value.trim();
        const pass = document.getElementById('password').value;
        const totpInput = document.getElementById('totp-code');
        const totpCode = totpInput ? totpInput.value.trim() : '';
        const errDiv = document.getElementById('login-error');

        try {
            errDiv.textContent = "Deriving keys...";
            errDiv.classList.remove('hidden');

            // STEP 1: Fetch salt from server (also tells us if 2FA is enabled)
            const saltRes = await fetch(`${API_URL}/api/v1/auth/salt/${encodeURIComponent(user)}`);
            if (!saltRes.ok) {
                throw new Error("User not found or connection error");
            }

            const saltData = await saltRes.json();
            const userSalt = saltData.salt;
            const is2faEnabled = saltData.is_2fa_enabled || false;

            // If 2FA enabled but no code provided, show 2FA input
            if (is2faEnabled && !totpCode) {
                show2FAInput();
                errDiv.textContent = "Enter your 2FA code from authenticator app";
                errDiv.classList.remove('bg-red-900/30', 'border-red-900', 'text-red-400');
                errDiv.classList.add('bg-blue-900/30', 'border-blue-900', 'text-blue-400');
                return;
            }

            // STEP 2: Derive Master Key from password + fetched salt
            state.masterKey = await deriveKeyFromPassword(pass, userSalt);

            // STEP 3: Derive Auth Key (Hash of Master Key)
            const authKey = await deriveAuthKey(state.masterKey);

            // STEP 4: Login with AuthKey (and optionally TOTP code)
            const formData = new URLSearchParams();
            formData.append('username', user);
            formData.append('password', authKey);  // AuthKey, NOT raw password
            if (totpCode) {
                formData.append('totp_code', totpCode);
            }

            const response = await fetch(`${API_URL}/api/v1/auth/login?totp_code=${encodeURIComponent(totpCode)}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: formData
            });

            if (!response.ok) {
                // Clear master key on failed login
                state.masterKey = null;
                const errorData = await response.json();

                // Check if 2FA is required
                if (response.headers.get('X-Requires-2FA') === 'true' || errorData.detail === '2FA code required') {
                    show2FAInput();
                    errDiv.textContent = "Enter your 2FA code from authenticator app";
                    errDiv.classList.remove('bg-red-900/30', 'border-red-900', 'text-red-400');
                    errDiv.classList.add('bg-blue-900/30', 'border-blue-900', 'text-blue-400');
                    return;
                }

                throw new Error(errorData.detail || "Incorrect username or password");
            }

            const data = await response.json();
            state.token = data.access_token;
            state.username = user;

            // Store token for API calls
            sessionStorage.setItem("access_token", data.access_token);

            // Switch to vault screen
            hide2FAInput();
            loginScreen.classList.add('hidden-screen');
            vaultScreen.classList.remove('hidden-screen');
            document.getElementById('user-display').textContent = user;
            errDiv.classList.add('hidden');

            // Load vault items
            loadVaultItems();

        } catch (err) {
            errDiv.textContent = err.message;
            errDiv.classList.remove('hidden');
            errDiv.classList.remove('bg-blue-900/30', 'border-blue-900', 'text-blue-400');
            errDiv.classList.add('bg-red-900/30', 'border-red-900', 'text-red-400');
            console.error("Login error:", err);
        }
    });

    // Helper functions for 2FA input visibility
    function show2FAInput() {
        const totpContainer = document.getElementById('totp-container');
        if (totpContainer) {
            totpContainer.classList.remove('hidden');
            document.getElementById('totp-code').focus();
        }
    }

    function hide2FAInput() {
        const totpContainer = document.getElementById('totp-container');
        if (totpContainer) {
            totpContainer.classList.add('hidden');
            document.getElementById('totp-code').value = '';
        }
    }

    // --- LOGOUT LOGIC ---
    document.getElementById('logout-btn').addEventListener('click', () => {
        // Clear all sensitive state
        state.token = null;
        state.masterKey = null;
        state.username = null;
        state.items = [];

        // Clear session storage
        sessionStorage.removeItem("access_token");

        // Reset 2FA input
        hide2FAInput();

        // Switch to login screen
        vaultScreen.classList.add('hidden-screen');
        loginScreen.classList.remove('hidden-screen');
        document.getElementById('login-form').reset();
        document.getElementById('password').value = "";
    });

    // --- EXPORT VAULT LOGIC (Offline Encrypted Backup) ---
    document.getElementById('export-vault-btn').addEventListener('click', async () => {
        try {
            if (!state.masterKey) {
                alert("❌ Error: Master key not available. Please log in again.");
                return;
            }

            if (!state.items || state.items.length === 0) {
                alert("❌ Error: Vault is empty. Nothing to export.");
                return;
            }

            // Prepare vault data for export (encrypted items only - no plaintext)
            const vaultExportData = state.items.map(item => ({
                id: item.id,
                label: item.label,
                encrypted_data: item.encrypted_data,
                iv: item.iv,
                risk_level: item.risk_level
            }));

            // Create backup structure
            const backupPayload = {
                version: 1,
                exported_at: new Date().toISOString(),
                items_count: vaultExportData.length,
                vault_items: vaultExportData
            };

            // Encrypt the entire backup payload using the master key
            const encrypted = await encryptBlob(backupPayload);

            // Create final backup file structure
            const backupFile = {
                version: 1,
                exported_at: new Date().toISOString(),
                ciphertext: encrypted.data,
                iv: encrypted.iv,
                encryption: "aes-gcm",
                kdf: "pbkdf2"
            };

            // Create and download the backup file
            const fileContent = JSON.stringify(backupFile, null, 2);
            const blob = new Blob([fileContent], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const downloadLink = document.createElement('a');
            downloadLink.href = url;
            downloadLink.download = 'pallium-vault.enc';

            // Trigger download
            document.body.appendChild(downloadLink);
            downloadLink.click();
            document.body.removeChild(downloadLink);
            URL.revokeObjectURL(url);

            alert("✅ Vault exported successfully!\n\nYour backup file 'pallium-vault.enc' has been downloaded.\n\n⚠️ This file is encrypted with your master password.\nKeep it safe for offline recovery.");

        } catch (err) {
            console.error("Export error:", err);
            alert("❌ Export failed: " + err.message);
        }
    });

    // --- UI EVENTS ---
    document.getElementById('toggle-raw').addEventListener('change', () => {
        renderGrid(state.items);
    });

    document.getElementById('search-input').addEventListener('input', (e) => {
        const keyword = e.target.value.toLowerCase();
        const filtered = state.items.filter(item =>
            item.label.toLowerCase().includes(keyword) ||
            (item.decrypted && item.decrypted.username.toLowerCase().includes(keyword))
        );
        renderGrid(filtered);
    });

    // --- SAVE NEW ITEM LOGIC ---
    document.getElementById('save-item-btn').addEventListener('click', async () => {
        try {
            const label = document.getElementById('item-label').value.trim();
            const username = document.getElementById('item-username').value.trim();
            const password = document.getElementById('item-password').value;
            const riskLevel = parseInt(document.getElementById('item-risk').value, 10) || 1;

            if (!label || !username || !password) {
                alert("Please fill in all fields.");
                return;
            }

            // Encrypt the secret data client-side
            const secretData = { username, password };
            const encrypted = await encryptBlob(secretData);

            const payload = {
                label: label,
                encrypted_data: encrypted.data,
                iv: encrypted.iv,
                risk_level: riskLevel
            };

            const res = await fetch(`${API_URL}/api/v1/vault/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${state.token}`
                },
                body: JSON.stringify(payload)
            });

            if (res.ok) {
                document.getElementById('add-modal').classList.add('hidden-screen');
                document.getElementById('add-form').reset();
                document.getElementById('item-password').type = 'password';
                loadVaultItems();
            } else {
                const err = await res.json();
                throw new Error("Save failed: " + JSON.stringify(err));
            }
        } catch (e) {
            alert(e.message);
            console.error("Save error:", e);
        }
    });
    // --- FORGOT PASSWORD (SEED RECOVERY ENTRY) ---
    const forgotBtn = document.getElementById('forgot-password-btn');
    const backBtn = document.getElementById('back-to-login-btn');

    if (forgotBtn && backBtn) {
        forgotBtn.addEventListener('click', (e) => {
            e.preventDefault();

            document.getElementById('login-screen').classList.add('hidden-screen');
            document.getElementById('recovery-screen').classList.remove('hidden-screen');

            console.log("🔑 Entered seed recovery mode");
        });

        backBtn.addEventListener('click', (e) => {
            e.preventDefault();

            document.getElementById('recovery-screen').classList.add('hidden-screen');
            document.getElementById('login-screen').classList.remove('hidden-screen');
        });
    }

    // ─────────────────────────────────────────────────────────────
    // 2FA SETUP & MANAGEMENT
    // ─────────────────────────────────────────────────────────────

    const twofaModal = document.getElementById('twofa-modal');
    const twofaSettingsBtn = document.getElementById('settings-2fa-btn');
    const twofaCloseBtn = document.getElementById('twofa-close-btn');
    const twofaEnableBtn = document.getElementById('twofa-enable-btn');
    const twofaVerifyBtn = document.getElementById('twofa-verify-btn');
    const twofaDisableBtn = document.getElementById('twofa-disable-btn');

    // Open 2FA modal
    if (twofaSettingsBtn) {
        twofaSettingsBtn.addEventListener('click', async () => {
            await load2FAStatus();
            twofaModal.classList.remove('hidden-screen');
        });
    }

    // Close 2FA modal
    if (twofaCloseBtn) {
        twofaCloseBtn.addEventListener('click', () => {
            twofaModal.classList.add('hidden-screen');
            reset2FAModal();
        });
    }

    // Load current 2FA status
    async function load2FAStatus() {
        try {
            const res = await fetch(`${API_URL}/api/v1/auth/2fa/status`, {
                headers: { 'Authorization': `Bearer ${state.token}` }
            });

            if (!res.ok) throw new Error('Failed to load 2FA status');

            const data = await res.json();
            const statusDiv = document.getElementById('twofa-status');
            const statusText = document.getElementById('twofa-status-text');

            if (data.is_enabled) {
                statusDiv.className = 'mb-4 p-3 rounded border border-green-700 bg-green-900/20';
                statusText.textContent = '✅ 2FA is currently ENABLED';
                statusText.className = 'text-sm text-green-400';

                document.getElementById('twofa-enable-btn').classList.add('hidden');
                document.getElementById('twofa-setup-step1').classList.add('hidden');
                document.getElementById('twofa-disable-section').classList.remove('hidden');
            } else {
                statusDiv.className = 'mb-4 p-3 rounded border border-yellow-700 bg-yellow-900/20';
                statusText.textContent = '⚠️ 2FA is currently DISABLED';
                statusText.className = 'text-sm text-yellow-400';

                document.getElementById('twofa-enable-btn').classList.remove('hidden');
                document.getElementById('twofa-setup-step1').classList.add('hidden');
                document.getElementById('twofa-disable-section').classList.add('hidden');
            }
        } catch (err) {
            console.error('Failed to load 2FA status:', err);
        }
    }

    // Start 2FA setup - get QR code
    if (twofaEnableBtn) {
        twofaEnableBtn.addEventListener('click', async () => {
            try {
                const res = await fetch(`${API_URL}/api/v1/auth/2fa/setup`, {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${state.token}` }
                });

                if (!res.ok) throw new Error('Failed to setup 2FA');

                const data = await res.json();

                // Display QR code (data.qr_code is base64 PNG)
                document.getElementById('twofa-qr-code').src = `data:image/png;base64,${data.qr_code}`;
                document.getElementById('twofa-secret').textContent = data.secret;

                // Show setup step
                document.getElementById('twofa-enable-btn').classList.add('hidden');
                document.getElementById('twofa-setup-step1').classList.remove('hidden');
                document.getElementById('twofa-verify-code').value = '';
                document.getElementById('twofa-verify-code').focus();

            } catch (err) {
                alert('Failed to setup 2FA: ' + err.message);
            }
        });
    }

    // Verify and enable 2FA
    if (twofaVerifyBtn) {
        twofaVerifyBtn.addEventListener('click', async () => {
            const code = document.getElementById('twofa-verify-code').value.trim();
            const errorDiv = document.getElementById('twofa-verify-error');

            if (code.length !== 6 || !/^\d+$/.test(code)) {
                errorDiv.textContent = 'Please enter a valid 6-digit code';
                errorDiv.classList.remove('hidden');
                return;
            }

            try {
                const res = await fetch(`${API_URL}/api/v1/auth/2fa/verify`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${state.token}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ code: code })
                });

                if (!res.ok) {
                    const err = await res.json();
                    throw new Error(err.detail || 'Verification failed');
                }

                // Success
                errorDiv.classList.add('hidden');
                alert('✅ 2FA has been enabled successfully!');
                await load2FAStatus();

            } catch (err) {
                errorDiv.textContent = err.message;
                errorDiv.classList.remove('hidden');
            }
        });
    }

    // Disable 2FA
    if (twofaDisableBtn) {
        twofaDisableBtn.addEventListener('click', async () => {
            const code = document.getElementById('twofa-disable-code').value.trim();
            const errorDiv = document.getElementById('twofa-disable-error');

            if (code.length !== 6 || !/^\d+$/.test(code)) {
                errorDiv.textContent = 'Please enter a valid 6-digit code';
                errorDiv.classList.remove('hidden');
                return;
            }

            if (!confirm('Are you sure you want to disable 2FA? This will make your account less secure.')) {
                return;
            }

            try {
                const res = await fetch(`${API_URL}/api/v1/auth/2fa/disable`, {
                    method: 'DELETE',
                    headers: {
                        'Authorization': `Bearer ${state.token}`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ code: code })
                });

                if (!res.ok) {
                    const err = await res.json();
                    throw new Error(err.detail || 'Failed to disable 2FA');
                }

                // Success
                errorDiv.classList.add('hidden');
                alert('2FA has been disabled.');
                await load2FAStatus();

            } catch (err) {
                errorDiv.textContent = err.message;
                errorDiv.classList.remove('hidden');
            }
        });
    }

    // Reset modal state
    function reset2FAModal() {
        document.getElementById('twofa-setup-step1').classList.add('hidden');
        document.getElementById('twofa-disable-section').classList.add('hidden');
        document.getElementById('twofa-verify-code').value = '';
        document.getElementById('twofa-disable-code').value = '';
        document.getElementById('twofa-verify-error').classList.add('hidden');
        document.getElementById('twofa-disable-error').classList.add('hidden');
    }

}

