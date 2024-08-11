# lockcrypt

`lockcrypt` is a powerful Node.js library for encrypting and decrypting data using symmetric and asymmetric encryption algorithms. It provides utility methods for password encryption, public/private key encryption, and RSA key pair generation.

## Features

- **Symmetric Encryption**: Encrypt and decrypt data using the AES-256-CBC algorithm by default.
- **Asymmetric Encryption**: Encrypt and decrypt data using RSA public/private key pairs.
- **RSA Key Pair Generation**: Easily generate RSA public/private key pairs with customizable modulus lengths.
- **Error Handling**: Provides detailed error messages to help you debug encryption/decryption issues.

## Installation

Install the package using npm:

```bash
npm install lockcrypt
```

## Usage

### Importing the Library

```javascript
const PasswordEncryption = require('lockcrypt');
```

### Symmetric Encryption

#### Encrypt a Password

```javascript
const secretKey = 'your-32-character-secret-key';
const password = 'your-password';
const encryptedPassword = PasswordEncryption.encrypt(secretKey, password);
console.log('Encrypted Password:', encryptedPassword);
```

#### Decrypt a Password

```javascript
const decryptedPassword = PasswordEncryption.decrypt(secretKey, encryptedPassword);
console.log('Decrypted Password:', decryptedPassword);
```

### Asymmetric Encryption

#### Encrypt Data with a Public Key

```javascript
const publicKey = 'your-public-key';
const data = 'data-to-encrypt';
const encryptedData = PasswordEncryption.encryptWithPublicKey(publicKey, data);
console.log('Encrypted Data:', encryptedData);
```

#### Decrypt Data with a Private Key

```javascript
const privateKey = 'your-private-key';
const decryptedData = PasswordEncryption.decryptWithPrivateKey(privateKey, encryptedData);
console.log('Decrypted Data:', decryptedData);
```

### RSA Key Pair Generation

```javascript
const { publicKey, privateKey } = PasswordEncryption.generateRSAKeyPair();
console.log('Public Key:', publicKey);
console.log('Private Key:', privateKey);
```

## Error Handling

`lockcrypt` provides meaningful error messages for various scenarios such as incorrect key lengths, invalid algorithm names, and more. Always wrap encryption and decryption operations in try/catch blocks to handle potential errors gracefully.

```javascript
try {
    const encryptedPassword = PasswordEncryption.encrypt(secretKey, password);
} catch (error) {
    console.error('Error:', error.message);
}
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
