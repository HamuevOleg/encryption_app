import { Elysia, t } from "elysia";
import { swagger } from "@elysiajs/swagger";
import { cors } from "@elysiajs/cors";
import {
  EncryptRequestDto,
  DecryptRequestDto,
  AesKeyResponseDto,
  AsymKeyPairResponseDto,
  EncryptResponseDto,
  DecryptResponseDto,
} from "./dto";
import {
  generateAesKey,
  encryptAes,
  decryptAes,
  generateRsaKeyPair,
  encryptRsa,
  decryptRsa,
  generateEccKeyPair,
  encryptEcc,
  decryptEcc,
  hashText
} from "./encryption.service";
import { config } from "./config";
import { logOperation } from "./db";

const app = new Elysia()
  .use(
    cors({
      origin: "http://localhost:4200",
      methods: ["GET", "POST", "OPTIONS"],
    })
  )
  .use(
    swagger({
      documentation: {
        info: {
          title: "Encryption API",
          version: "1.0.0",
          description: "REST API for AES, RSA, ECC encryption and key generation"
        }
      }
    })
  )
  .post(
    "/encrypt",
    async ({ body }) => {
      const req = body as EncryptRequestDto;
      const start = performance.now();

      try {
        let encryptedText: string;
        switch (req.method) {
          case "AES":
            if (!req.key) throw new Error("AES requires 'key'.");
            encryptedText = encryptAes(req.text, req.key);
            break;
          case "RSA":
            if (!req.publicKey) throw new Error("RSA requires 'publicKey' for encryption.");
            encryptedText = encryptRsa(req.text, req.publicKey);
            break;
          case "ECC":
            if (!req.publicKey) throw new Error("ECC requires 'publicKey' for encryption.");
            encryptedText = encryptEcc(req.text, req.publicKey);
            break;
          default:
            throw new Error("Unsupported method.");
        }

        const executionTimeMs = performance.now() - start;
        const textHash = hashText(req.text);

        void logOperation({
          method: req.method,
          operationType: "encrypt",
          textHash,
          executionTimeMs,
        });

        const response: EncryptResponseDto = {
          encryptedText,
          method: req.method,
          executionTimeMs,
        };
        return response;
      } catch (err: any) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }
    },
    {
      body: t.Object({
        method: t.Union([t.Literal("AES"), t.Literal("RSA"), t.Literal("ECC")]),
        text: t.String(),
        key: t.Optional(t.String()),
        publicKey: t.Optional(t.String())
      }),
      response: {
        200: t.Object({
          encryptedText: t.String(),
          method: t.Union([t.Literal("AES"), t.Literal("RSA"), t.Literal("ECC")]),
          executionTimeMs: t.Number(),
        }),
        400: t.Object({ error: t.String() }),
      },
      detail: { summary: "Encrypt text", tags: ["Encryption"] }
    }
  )
  .post(
    "/decrypt",
    async ({ body }) => {
      const req = body as DecryptRequestDto;
      const start = performance.now();

      try {
        let decryptedText: string;
        switch (req.method) {
          case "AES":
            if (!req.key) throw new Error("AES requires 'key'.");
            decryptedText = decryptAes(req.encryptedText, req.key);
            break;
          case "RSA":
            if (!req.privateKey) throw new Error("RSA requires 'privateKey' for decryption.");
            decryptedText = decryptRsa(req.encryptedText, req.privateKey);
            break;
          case "ECC":
            if (!req.privateKey) throw new Error("ECC requires 'privateKey' for decryption.");
            decryptedText = decryptEcc(req.encryptedText, req.privateKey);
            break;
          default:
            throw new Error("Unsupported method.");
        }

        const executionTimeMs = performance.now() - start;
        const textHash = hashText(decryptedText);

        void logOperation({
          method: req.method,
          operationType: "decrypt",
          textHash,
          executionTimeMs,
        });

        const response: DecryptResponseDto = {
          decryptedText,
          method: req.method,
          executionTimeMs,
        };
        return response;
      } catch (err: any) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 400,
          headers: { "Content-Type": "application/json" }
        });
      }
    },
    {
      body: t.Object({
        method: t.Union([t.Literal("AES"), t.Literal("RSA"), t.Literal("ECC")]),
        encryptedText: t.String(),
        key: t.Optional(t.String()),
        privateKey: t.Optional(t.String())
      }),
      response: {
        200: t.Object({
          decryptedText: t.String(),
          method: t.Union([t.Literal("AES"), t.Literal("RSA"), t.Literal("ECC")]),
          executionTimeMs: t.Number(),
        }),
        400: t.Object({ error: t.String() }),
      },
      detail: { summary: "Decrypt text", tags: ["Decryption"] }
    }
  )
  .post(
    "/generate-key/aes",
    () => {
      const key = generateAesKey();
      const res: AesKeyResponseDto = { key };
      return res;
    },
    {
      response: t.Object({ key: t.String() }),
      detail: { summary: "Generate AES symmetric key", tags: ["Key Generation"] }
    }
  )
  .post(
    "/generate-key/rsa",
    () => {
      const pair = generateRsaKeyPair();
      const res: AsymKeyPairResponseDto = pair;
      return res;
    },
    {
      response: t.Object({ publicKey: t.String(), privateKey: t.String() }),
      detail: { summary: "Generate RSA key pair", tags: ["Key Generation"] }
    }
  )
  .post(
    "/generate-key/ecc",
    () => {
      const pair = generateEccKeyPair();
      const res: AsymKeyPairResponseDto = pair;
      return res;
    },
    {
      response: t.Object({ publicKey: t.String(), privateKey: t.String() }),
      detail: { summary: "Generate ECC key pair (P-256)", tags: ["Key Generation"] }
    }
  )
  .get("/health", () => ({ status: "ok" }), {
    detail: { summary: "Health check", tags: ["Health"] }
  });

app.listen(config.port);
console.log(`Encryption API listening on port ${config.port}`);
console.log("Swagger UI available at /swagger");
