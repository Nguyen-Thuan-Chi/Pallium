// frontend/js/crypto.js

// ===== CẤU HÌNH THUẬT TOÁN =====
const PBKDF2_ITERATIONS = 100000;
const IV_LENGTH = 12;        // 96 bits cho AES-GCM
const KEY_LENGTH = 256;

// ===== TEXT ENCODER / DECODER =====
const enc = new TextEncoder();
const dec = new TextDecoder();

// ===== BUFFER <-> HEX =====
function buffToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

// QUY ƯỚC: hexToBuff LUÔN TRẢ VỀ ArrayBuffer
function hexToBuff(hexString) {
    if (!hexString) return new ArrayBuffer(0);

    const hex = hexString.replace(/\s/g, '');
    if (hex.length % 2 !== 0) {
        throw new Error("Invalid hex string");
    }

    const bytes = new Uint8Array(
        hex.match(/.{1,2}/g).map(b => parseInt(b, 16))
    );

    return bytes.buffer;
}

// ===== 1. DERIVE KEY (PBKDF2) =====
// password: string
// saltHex: hex string (từ backend)
export async function deriveKeyFromPassword(password, saltHex) {
    const passwordKey = await crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    const saltBuffer = hexToBuff(saltHex);

    return await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: saltBuffer,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256",
        },
        passwordKey,
        { name: "AES-GCM", length: KEY_LENGTH },
        false, // key không export
        ["encrypt", "decrypt"]
    );
}

// ===== 2. ENCRYPT (AES-GCM) =====
export async function encryptData(dataObj, key) {
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const plaintext = enc.encode(JSON.stringify(dataObj));

    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        plaintext
    );

    return {
        encrypted_data: buffToHex(ciphertext), // gồm cả auth tag
        iv: buffToHex(iv.buffer)
    };
}

// ===== 3. DECRYPT (AES-GCM) =====
export async function decryptData(encryptedHex, ivHex, key) {
    try {
        const encryptedBuffer = hexToBuff(encryptedHex);
        const ivBuffer = hexToBuff(ivHex);

        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: ivBuffer },
            key,
            encryptedBuffer
        );

        return JSON.parse(dec.decode(decrypted));
    } catch (e) {
        console.error("Decryption failed", e);
        throw new Error("Failed to decrypt. Wrong password?");
    }
}
