const crypto = require('crypto');

class PasswordEncryption {
    /**
     * Encrypts a given password using the specified symmetric algorithm.
     * @param {string} secretKey - The secret key for symmetric encryption (32 characters).
     * @param {string} password - The plaintext password to encrypt.
     * @param {string} [algorithm='aes-256-cbc'] - The encryption algorithm to use.
     * @returns {string} The encrypted password in the format 'iv:encrypted'.
     * @throws Will throw an error if encryption fails.
     */
    static encrypt(secretKey, password, algorithm = 'aes-256-cbc') {
        if (typeof secretKey !== 'string' || secretKey.length !== 32) {
            throw new Error('Secret key must be a string of 32 characters long');
        }

        if (typeof password !== 'string') {
            throw new Error('Password must be a string');
        }

        if (typeof algorithm !== 'string' || !crypto.getCiphers().includes(algorithm)) {
            throw new Error(`Algorithm ${algorithm} is not supported or is not a valid string`);
        }

        try {
            const iv = crypto.randomBytes(16); // For AES, IV is always 16 bytes
            const cipher = crypto.createCipheriv(algorithm, Buffer.from(secretKey), iv);
            let encrypted = cipher.update(password, 'utf-8', 'hex');
            encrypted += cipher.final('hex');
            return iv.toString('hex') + ':' + encrypted;
        } catch (error) {
            throw new Error('Encryption failed: ' + error.message);
        }
    }

    /**
     * Decrypts an encrypted password using the specified symmetric algorithm.
     * @param {string} secretKey - The secret key for symmetric decryption (32 characters).
     * @param {string} encryptedPassword - The encrypted password in the format 'iv:encrypted'.
     * @param {string} [algorithm='aes-256-cbc'] - The encryption algorithm to use.
     * @returns {string} The decrypted plaintext password.
     * @throws Will throw an error if decryption fails.
     */
    static decrypt(secretKey, encryptedPassword, algorithm = 'aes-256-cbc') {
        if (typeof secretKey !== 'string' || secretKey.length !== 32) {
            throw new Error('Secret key must be a string of 32 characters long');
        }

        if (typeof encryptedPassword !== 'string') {
            throw new Error('Encrypted password must be a string');
        }

        if (typeof algorithm !== 'string' || !crypto.getCiphers().includes(algorithm)) {
            throw new Error(`Algorithm ${algorithm} is not supported or is not a valid string`);
        }

        try {
            const [ivHex, encrypted] = encryptedPassword.split(':');
            if (!ivHex || !encrypted) {
                throw new Error('Invalid encrypted password format');
            }

            const iv = Buffer.from(ivHex, 'hex');
            const decipher = crypto.createDecipheriv(algorithm, Buffer.from(secretKey), iv);
            let decrypted = decipher.update(encrypted, 'hex', 'utf-8');
            decrypted += decipher.final('utf-8');
            return decrypted;
        } catch (error) {
            throw new Error('Decryption failed: ' + error.message);
        }
    }

    /**
     * Encrypts data using an asymmetric public key.
     * @param {string|Buffer} publicKey - The public key for encryption.
     * @param {string} data - The data to encrypt.
     * @returns {string} The encrypted data in base64 format.
     * @throws Will throw an error if encryption fails.
     */
    static encryptWithPublicKey(publicKey, data) {
        if (typeof publicKey !== 'string' && !Buffer.isBuffer(publicKey)) {
            throw new Error('Public key must be a string or Buffer');
        }

        if (typeof data !== 'string') {
            throw new Error('Data to encrypt must be a string');
        }

        try {
            const buffer = Buffer.from(data);
            const encrypted = crypto.publicEncrypt(publicKey, buffer);
            return encrypted.toString('base64');
        } catch (error) {
            throw new Error('Asymmetric encryption failed: ' + error.message);
        }
    }

    /**
     * Decrypts data using an asymmetric private key.
     * @param {string|Buffer} privateKey - The private key for decryption.
     * @param {string} encryptedData - The encrypted data in base64 format.
     * @returns {string} The decrypted plaintext data.
     * @throws Will throw an error if decryption fails.
     */
    static decryptWithPrivateKey(privateKey, encryptedData) {
        if (typeof privateKey !== 'string' && !Buffer.isBuffer(privateKey)) {
            throw new Error('Private key must be a string or Buffer');
        }

        if (typeof encryptedData !== 'string') {
            throw new Error('Encrypted data must be a string in base64 format');
        }

        try {
            const buffer = Buffer.from(encryptedData, 'base64');
            const decrypted = crypto.privateDecrypt(privateKey, buffer);
            return decrypted.toString('utf-8');
        } catch (error) {
            throw new Error('Asymmetric decryption failed: ' + error.message);
        }
    }

    /**
     * Generates an RSA key pair.
     * @param {number} [modulusLength=2048] - The length of the RSA key in bits.
     * @returns {object} An object containing the generated publicKey and privateKey.
     * @throws Will throw an error if key generation fails.
     */
    static generateRSAKeyPair(modulusLength = 2048) {
        if (typeof modulusLength !== 'number' || modulusLength < 2048) {
            throw new Error('Modulus length must be a number greater than or equal to 2048');
        }

        try {
            const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
                modulusLength,
                publicKeyEncoding: { type: 'spki', format: 'pem' },
                privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
            });

            return { publicKey, privateKey };
        } catch (error) {
            throw new Error('RSA key pair generation failed: ' + error.message);
        }
    }
}

module.exports = PasswordEncryption;
