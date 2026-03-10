export declare function decryptPDF(
  pdfBytes: Uint8Array,
  password: string
): Promise<Uint8Array>;

export declare function isEncrypted(
  pdfBytes: Uint8Array
): Promise<{
  encrypted: boolean;
  algorithm?: 'AES-256' | 'RC4';
  version?: number;
  revision?: number;
  keyLength?: number;
}>;

export declare function md5(data: Uint8Array | string): Uint8Array;
export declare class RC4 {
  constructor(key: Uint8Array);
  process(data: Uint8Array): Uint8Array;
}
export declare function hexToBytes(hex: string): Uint8Array;
export declare function bytesToHex(bytes: Uint8Array): string;

export declare function sha256(data: Uint8Array): Promise<Uint8Array>;
export declare function sha384(data: Uint8Array): Promise<Uint8Array>;
export declare function sha512(data: Uint8Array): Promise<Uint8Array>;
export declare function aes256CbcDecrypt(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array>;
export declare function aes256CbcDecryptNoPad(ciphertext: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array>;
export declare function aes256EcbDecryptBlock(block: Uint8Array, key: Uint8Array): Promise<Uint8Array>;
export declare function importAES256DecryptKey(key: Uint8Array): Promise<CryptoKey>;
export declare function aes256CbcDecryptWithKey(data: Uint8Array, cryptoKey: CryptoKey, iv: Uint8Array): Promise<Uint8Array>;
export declare function computeHash2B(password: Uint8Array, salt: Uint8Array, userKey: Uint8Array): Promise<Uint8Array>;
export declare function concat(...arrays: Uint8Array[]): Uint8Array;
