import { WORDLIST } from './wordlist.js';
import { apiRequest } from './api.js';

/**
 * Generate a seed phrase by randomly selecting words from the wordlist
 * @param {number} wordCount - Number of words (default 12)
 * @returns {string} Space-separated seed phrase
 */
export function generateSeedPhrase(wordCount = 12) {
    if (wordCount < 1 || wordCount > 24) {
        throw new Error('Word count must be between 1 and 24');
    }

    const randomBytes = new Uint8Array(wordCount * 2);
    crypto.getRandomValues(randomBytes);

    const words = [];
    for (let i = 0; i < wordCount; i++) {
        const randomValue = (randomBytes[i * 2] << 8) | randomBytes[i * 2 + 1];
        const index = randomValue % WORDLIST.length;
        words.push(WORDLIST[index]);
    }

    return words.join(' ');
}

/**
 * Generate a random salt for key derivation
 * @param {number} length - Salt length in bytes (default 16)
 * @returns {Uint8Array} Random salt
 */
export function generateSalt(length = 16) {
    const salt = new Uint8Array(length);
    crypto.getRandomValues(salt);
    return salt;
}

/**
 * Derive a verifier from seed phrase using PBKDF2
 * @param {string} seedPhrase - The seed phrase
 * @param {Uint8Array} salt - Salt for key derivation
 * @returns {Promise<string>} Base64-encoded verifier
 */
export async function deriveSeedVerifier(seedPhrase, salt) {
    const encoder = new TextEncoder();
    const seedBytes = encoder.encode(seedPhrase.trim().toLowerCase());

    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        seedBytes,
        'PBKDF2',
        false,
        ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 200000,
            hash: 'SHA-256'
        },
        keyMaterial,
        256
    );

    const verifierBytes = new Uint8Array(derivedBits);
    return uint8ArrayToBase64(verifierBytes);
}

/**
 * Convert Uint8Array to Base64 string
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function uint8ArrayToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * Convert Base64 string to Uint8Array
 * @param {string} base64
 * @returns {Uint8Array}
 */
function base64ToUint8Array(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 * Setup seed recovery - stores verifier on server
 * @param {string} seedPhrase - The seed phrase (shown to user, never stored)
 * @returns {Promise<{success: boolean}>}
 */
export async function setupSeedRecovery(seedPhrase) {
    const salt = generateSalt();
    const verifier = await deriveSeedVerifier(seedPhrase, salt);

    const response = await apiRequest('/api/v1/seed/setup', {
        method: 'POST',
        body: JSON.stringify({
            verifier: verifier,
            salt: uint8ArrayToBase64(salt)
        })
    });

    return response;
}

/**
 * Verify seed phrase for account recovery
 * @param {string} seedPhrase - The seed phrase entered by user
 * @param {string} saltBase64 - Salt from server (base64)
 * @returns {Promise<{success: boolean, recovery_token?: string}>}
 */
export async function verifySeedForRecovery(seedPhrase, saltBase64) {
    const salt = base64ToUint8Array(saltBase64);
    const verifier = await deriveSeedVerifier(seedPhrase, salt);

    const response = await apiRequest('/api/v1/seed/verify', {
        method: 'POST',
        body: JSON.stringify({
            verifier: verifier
        })
    });

    return response;
}

/**
 * Get salt for recovery (before verification)
 * @param {string} email - User email
 * @returns {Promise<{salt: string}>}
 */
export async function getRecoverySalt(email) {
    const response = await apiRequest('/api/v1/seed/salt', {
        method: 'POST',
        body: JSON.stringify({
            email: email
        })
    });

    return response;
}
