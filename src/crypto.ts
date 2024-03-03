import { webcrypto } from 'crypto';

// Converts an ArrayBuffer to a base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString('base64');
}

// Converts a base64 string to an ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const buff = Buffer.from(base64, 'base64');
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// Generates an RSA key pair
export async function generateRsaKeyPair() {
  const keyPair = await webcrypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt']
  );
  return { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey };
}

// Exports a public key as a base64 string
export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  try {
    const exportedPubKey = await webcrypto.subtle.exportKey("spki", key);
    return arrayBufferToBase64(exportedPubKey);
  } catch (err) {
    console.error("Error exporting public key:", err);
    throw err;
  }
}

// Exports a private key as a base64 string
export async function exportPrvKey(key: webcrypto.CryptoKey | null): Promise<string | null> {
  try {
    if (key === null) {
      return null;
    } else {
      const exportedPrivKey = await webcrypto.subtle.exportKey("pkcs8", key);
      return arrayBufferToBase64(exportedPrivKey);
    }
  } catch (err) {
    console.error("Error exporting private key:", err);
    throw err;
  }
}

// Imports a public key from a base64 string
export async function importPubKey(strKey: string): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey(
    'spki',
    keyBuffer,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );
}

// Imports a private key from a base64 string
export async function importPrvKey(strKey: string): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey(
    'pkcs8',
    keyBuffer,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt']
  );
}

// Encrypts data using RSA-OAEP algorithm with a public key
export async function rsaEncrypt(b64Data: string, strPublicKey: string): Promise<string> {
  const publicKey = await importPubKey(strPublicKey);
  const data = base64ToArrayBuffer(b64Data);
  const encrypted = await webcrypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, data);
  return arrayBufferToBase64(encrypted);
}

// Decrypts data using RSA-OAEP algorithm with a private key
export async function rsaDecrypt(data: string, privateKey: webcrypto.CryptoKey): Promise<string> {
  const encryptedData = base64ToArrayBuffer(data);
  const decrypted = await webcrypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, encryptedData);
  const decoder = new TextDecoder();
  return arrayBufferToBase64(new Uint8Array(decrypted));
}

// Creates a random symmetric key for AES-CBC encryption
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  return await webcrypto.subtle.generateKey(
    { name: 'AES-CBC', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

// Exports a symmetric key as a base64 string
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  const exportedKey = await webcrypto.subtle.exportKey('raw', key);
  return arrayBufferToBase64(exportedKey);
}

// Imports a symmetric key from a base64 string
export async function importSymKey(strKey: string): Promise<webcrypto.CryptoKey> {
  const keyBuffer = base64ToArrayBuffer(strKey);
  return await webcrypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'AES-CBC', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

// Encrypts data using AES-CBC algorithm with a symmetric key
export async function symEncrypt(key: webcrypto.CryptoKey, data: string): Promise<string> {
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);
  const iv = webcrypto.getRandomValues(new Uint8Array(16));
  const encryptedData = await webcrypto.subtle.encrypt(
    { name: "AES-CBC", iv: iv },
    key,
    encodedData
  );
  const combinedIvAndData = new Uint8Array(iv.length + encryptedData.byteLength);
  combinedIvAndData.set(iv, 0);
  combinedIvAndData.set(new Uint8Array(encryptedData), iv.length);
  return arrayBufferToBase64(combinedIvAndData);
}

// Decrypts data using AES-CBC algorithm with a symmetric key
export async function symDecrypt(strKey: string, encryptedData: string): Promise<string> {
  const symKey = await importSymKey(strKey);
  const combinedIvAndData = base64ToArrayBuffer(encryptedData);
  const iv = combinedIvAndData.slice(0, 16);
  const data = combinedIvAndData.slice(16);
  const decryptedData = await webcrypto.subtle.decrypt(
    { name: "AES-CBC", iv: new Uint8Array(iv) },
    symKey,
    data
  );
  const decoder = new TextDecoder();
  return decoder.decode(decryptedData);
}
