import crypto from 'crypto';

function encryptWithAesGcm({ key, value }) {
  const hash = crypto.createHash('sha256').update(key).digest();
  
  const nonce = crypto.randomBytes(12);
  
  const cipher = crypto.createCipheriv('aes-256-gcm', hash, nonce);
  
  const ciphertext = Buffer.concat([
    cipher.update(value),
    cipher.final()
  ]);
  
  const authTag = cipher.getAuthTag();
  
  const result = Buffer.concat([nonce, ciphertext, authTag]);
  
  return result.toString('base64');
}

const testVectors = [
  { password: 'mypassword', plaintext: 'helloworld' },
  { password: 'test123', plaintext: 'test data' },
  { password: 'SecurePassword123!', plaintext: 'This is a longer test message.' }
];

console.log('// Generated test vectors for AES-GCM decryption');
console.log('// Format: { password, base64Data, expectedText }\n');

for (const { password, plaintext } of testVectors) {
  const encrypted = encryptWithAesGcm({
    key: password,
    value: Buffer.from(plaintext, 'utf-8')
  });
  
  console.log(`{ password: '${password}', data: '${encrypted}', expected: '${plaintext}' },`);
}
