import { Component, computed, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { HttpClientModule } from '@angular/common/http';
import { EncryptionApiService } from './services/encryption-api.service';
import {
  EncryptionMethod,
  AsymKeyPairResponse,
  EncryptResponse,
  DecryptResponse,
} from './models/encryption.models';

interface AlgorithmInfo {
  id: EncryptionMethod;
  name: string;
  short: string;
  description: string;
  howItWorks: string;
  pros: string[];
  cons: string[];
  uses: string[];
}

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [CommonModule, FormsModule, HttpClientModule],
  templateUrl: './app.html',
  styleUrl: './app.scss',
})
export class App {
  readonly title = signal('Encryption Playground');

  // State
  readonly selectedMethod = signal<EncryptionMethod>('AES');
  readonly plaintext = signal('');
  readonly encryptedText = signal('');

  // Keys
  readonly aesKey = signal('');
  readonly rsaPublicKey = signal('');
  readonly rsaPrivateKey = signal('');
  readonly eccPublicKey = signal('');
  readonly eccPrivateKey = signal('');

  // UI State
  readonly isLoading = signal(false);
  readonly errorMessage = signal('');
  readonly infoMessage = signal('');
  readonly lastExecutionTimeMs = signal<number | null>(null);
  readonly lastOperation = signal<'encrypt' | 'decrypt' | null>(null);
  readonly isVisualizing = signal(false);

  // Copy Button Logic
  readonly copyButtonLabel = signal('Copy Result');

  // Show button on right (Encrypted box) only if we just encrypted
  readonly showEncryptCopy = computed(() =>
    !this.isLoading() &&
    this.lastOperation() === 'encrypt' &&
    this.encryptedText().length > 0
  );

  // Show button on left (Plaintext box) only if we just decrypted
  readonly showDecryptCopy = computed(() =>
    !this.isLoading() &&
    this.lastOperation() === 'decrypt' &&
    this.plaintext().length > 0
  );

  // Modals
  readonly showAlgorithmModal = signal(false);
  readonly showKeyModal = signal(false);
  readonly activeAlgorithmInfo = signal<AlgorithmInfo | undefined>(undefined);

  readonly aesKeyExample = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6...';

  // Helper for visualization (Binary representation)
  readonly plainBits = computed(() => this.toBinary(this.plaintext()));
  readonly cipherBits = computed(() => this.toBinary(this.encryptedText()));

  readonly algorithms = signal<AlgorithmInfo[]>([
    {
      id: 'AES',
      name: 'AES',
      short: 'Advanced Encryption Standard (Symmetric)',
      description: 'AES is the global standard for symmetric encryption. It treats data as blocks and scrambles them using a secret key.',
      howItWorks: 'Data is put into a 4x4 grid. 1. SubBytes (replace bytes) 2. ShiftRows (move rows) 3. MixColumns (math magic) 4. AddRoundKey. This repeats 10-14 times.',
      pros: ['Extremely fast', 'Quantum resistant (256-bit)', 'Hardware accelerated'],
      cons: ['Key distribution is hard', 'One key compromises everything'],
      uses: ['WiFi (WPA2)', 'HTTPS', 'File Encryption'],
    },
    {
      id: 'RSA',
      name: 'RSA',
      short: 'Rivest–Shamir–Adleman (Asymmetric)',
      description: 'RSA relies on the mathematical difficulty of factoring the product of two large prime numbers.',
      howItWorks: 'Uses modular exponentiation. C = M^e mod n (Encrypt), M = C^d mod n (Decrypt). Public key is (e, n), Private is (d, n).',
      pros: ['Secure key exchange', 'Digital signatures', 'No shared secret needed beforehand'],
      cons: ['Slow', 'Large key sizes (2048+ bits)', 'Vulnerable to quantum computers'],
      uses: ['SSL/TLS Certificates', 'Email signatures (PGP)'],
    },
    {
      id: 'ECC',
      name: 'ECC',
      short: 'Elliptic Curve Cryptography (Asymmetric)',
      description: 'ECC creates keys based on the mathematics of elliptic curves over finite fields.',
      howItWorks: 'Points on a curve y² = x³ + ax + b. Adding a point to itself N times creates a "trapdoor" function. Hard to reverse.',
      pros: ['Very efficient', 'Small keys (256-bit ECC ≈ 3072-bit RSA)', 'Low power consumption'],
      cons: ['Complex implementation', 'Quantum vulnerable'],
      uses: ['Bitcoin/Blockchain', 'iMessage', 'Modern SSL'],
    },
  ]);

  readonly keyExplanation = {
    title: 'What is an encryption key?',
    paragraphs: [
      'Think of a key as a unique password in binary format.',
      'Symmetric (AES): Like a house key. The same key locks and unlocks the door. You must give a copy to your friend safely.',
      'Asymmetric (RSA/ECC): Like a mailbox. Anyone can drop a letter in (Public Key), but only you have the key to open the box and read it (Private Key).',
    ],
  };

  readonly selectedAlgorithm = computed(() =>
    this.algorithms().find((a) => a.id === this.selectedMethod())
  );

  constructor(private readonly api: EncryptionApiService) {}

  setMethod(method: EncryptionMethod): void {
    this.selectedMethod.set(method);
    this.resetState();
  }

  resetState() {
    this.errorMessage.set('');
    this.infoMessage.set('');
    this.isVisualizing.set(false);
    this.lastOperation.set(null);
    this.copyButtonLabel.set('Copy Result');
  }

  toBinary(input: string): string {
    if (!input) return '';
    return input.split('').map(char =>
      char.charCodeAt(0).toString(2).padStart(8, '0')
    ).join(' ').substring(0, 300) + (input.length > 35 ? '...' : '');
  }

  openAlgorithmModal(alg: AlgorithmInfo): void {
    this.activeAlgorithmInfo.set(alg);
    this.showAlgorithmModal.set(true);
  }

  closeAlgorithmModal(): void { this.showAlgorithmModal.set(false); }
  openKeyModal(): void { this.showKeyModal.set(true); }
  closeKeyModal(): void { this.showKeyModal.set(false); }

  onEncrypt(): void {
    this.resetState();
    this.isVisualizing.set(true);

    if (!this.plaintext().trim()) {
      this.errorMessage.set('Please enter some text to encrypt.');
      this.isVisualizing.set(false);
      return;
    }

    const method = this.selectedMethod();
    const body: any = { method, text: this.plaintext() };

    if (method === 'AES') {
      if (!this.aesKey()) {
        this.errorMessage.set('AES requires a key.'); this.isVisualizing.set(false); return;
      }
      body.key = this.aesKey();
    } else if (method === 'RSA') {
      if (!this.rsaPublicKey()) {
        this.errorMessage.set('RSA requires a public key.'); this.isVisualizing.set(false); return;
      }
      body.publicKey = this.rsaPublicKey();
    } else if (method === 'ECC') {
      if (!this.eccPublicKey()) {
        this.errorMessage.set('ECC requires a public key.'); this.isVisualizing.set(false); return;
      }
      body.publicKey = this.eccPublicKey();
    }

    this.isLoading.set(true);
    this.api.encrypt(body).subscribe({
      next: (res: EncryptResponse) => {
        setTimeout(() => {
          this.encryptedText.set(res.encryptedText);
          this.lastExecutionTimeMs.set(res.executionTimeMs);
          this.lastOperation.set('encrypt');
          this.infoMessage.set(`Encrypted successfully!`);
          this.isLoading.set(false);
        }, 800);
      },
      error: (err) => {
        this.errorMessage.set(err.error?.error || 'Encryption failed.');
        this.isLoading.set(false);
        this.isVisualizing.set(false);
      },
    });
  }

  onDecrypt(): void {
    this.resetState();
    this.isVisualizing.set(true);

    if (!this.encryptedText().trim()) {
      this.errorMessage.set('Please provide encrypted text.');
      this.isVisualizing.set(false);
      return;
    }

    const method = this.selectedMethod();
    const body: any = { method, encryptedText: this.encryptedText() };

    if (method === 'AES') {
      if (!this.aesKey()) { this.errorMessage.set('AES key missing.'); this.isVisualizing.set(false); return; }
      body.key = this.aesKey();
    } else if (method === 'RSA') {
      if (!this.rsaPrivateKey()) { this.errorMessage.set('RSA private key missing.'); this.isVisualizing.set(false); return; }
      body.privateKey = this.rsaPrivateKey();
    } else if (method === 'ECC') {
      if (!this.eccPrivateKey()) { this.errorMessage.set('ECC private key missing.'); this.isVisualizing.set(false); return; }
      body.privateKey = this.eccPrivateKey();
    }

    this.isLoading.set(true);
    this.api.decrypt(body).subscribe({
      next: (res: DecryptResponse) => {
        setTimeout(() => {
          this.plaintext.set(res.decryptedText);
          this.lastExecutionTimeMs.set(res.executionTimeMs);
          this.lastOperation.set('decrypt');
          this.infoMessage.set(`Decrypted successfully!`);
          this.isLoading.set(false);
        }, 800);
      },
      error: (err) => {
        this.errorMessage.set(err.error?.error || 'Decryption failed.');
        this.isLoading.set(false);
        this.isVisualizing.set(false);
      },
    });
  }

  copyResult(): void {
    let textToCopy = '';
    // Check last operation to decide what to copy
    if (this.lastOperation() === 'encrypt') {
      textToCopy = this.encryptedText();
    } else if (this.lastOperation() === 'decrypt') {
      textToCopy = this.plaintext();
    }

    if (textToCopy) {
      navigator.clipboard.writeText(textToCopy).then(() => {
        this.copyButtonLabel.set('Copied! ✓');
        setTimeout(() => this.copyButtonLabel.set('Copy Result'), 2000);
      });
    }
  }

  // Key Generators
  onGenerateAesKey(): void {
    this.isLoading.set(true);
    this.api.generateAesKey().subscribe({
      next: (res) => { this.aesKey.set(res.key); this.isLoading.set(false); },
      error: () => { this.errorMessage.set('Error generating key'); this.isLoading.set(false); }
    });
  }

  onGenerateRsaKeys(): void {
    this.isLoading.set(true);
    this.api.generateRsaKeys().subscribe({
      next: (res) => { this.rsaPublicKey.set(res.publicKey); this.rsaPrivateKey.set(res.privateKey); this.isLoading.set(false); },
      error: () => { this.errorMessage.set('Error generating keys'); this.isLoading.set(false); }
    });
  }

  onGenerateEccKeys(): void {
    this.isLoading.set(true);
    this.api.generateEccKeys().subscribe({
      next: (res) => { this.eccPublicKey.set(res.publicKey); this.eccPrivateKey.set(res.privateKey); this.isLoading.set(false); },
      error: () => { this.errorMessage.set('Error generating keys'); this.isLoading.set(false); }
    });
  }
}
