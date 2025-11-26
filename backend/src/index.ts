import { Elysia } from "elysia";
import { swagger } from "@elysiajs/swagger";
import { cors } from "@elysiajs/cors";
import { EncryptionService } from "./encryption.service";
import { config } from "./config";
import {
    GenerateAesKeyQuery,
    EncryptBody,
    DecryptBody,
    EncryptResponse,
    DecryptResponse,
    AesKeyResponse,
    AsymKeyResponse
} from "./dto";

const app = new Elysia()
    .decorate('service', new EncryptionService())
    .use(cors({
        origin: true, // Разрешаем все для разработки
        methods: ["GET", "POST", "OPTIONS"],
    }))
    .use(swagger({
        documentation: {
            info: {
                title: "Encryption API",
                version: "1.1.0",
                description: "API with AES Key Size Selection"
            }
        }
    }))

    // --- KEY GENERATION ENDPOINTS ---

    // Генерация AES ключа (GET, так как это получение данных без побочных эффектов на сервере)
    // Поддерживает query param: ?size=128|192|256
    .get("/keys/aes", ({ query, service }) => {
        return service.generateAesKey(query.size || 256);
    }, {
        query: GenerateAesKeyQuery,
        response: AesKeyResponse,
        detail: { summary: "Generate AES Key", tags: ["Keys"] }
    })

    .post("/keys/rsa", ({ service }) => {
        return service.generateRsaKeys();
    }, {
        response: AsymKeyResponse,
        detail: { summary: "Generate RSA Keys", tags: ["Keys"] }
    })

    .post("/keys/ecc", ({ service }) => {
        return service.generateEccKeys();
    }, {
        response: AsymKeyResponse,
        detail: { summary: "Generate ECC Keys", tags: ["Keys"] }
    })

    // --- OPERATIONS ENDPOINTS ---

    .post("/encrypt", ({ body, service, error }) => {
        try {
            if (body.method === 'AES') {
                if (!body.key) return error(400, { error: 'AES requires a key' });
                const res = service.encryptAes(body.text, body.key);
                return { method: 'AES', ...res };
            }
            if (body.method === 'RSA') {
                if (!body.publicKey) return error(400, { error: 'RSA requires a public key' });
                const res = service.encryptRsa(body.text, body.publicKey);
                return { method: 'RSA', ...res };
            }
            if (body.method === 'ECC') {
                if (!body.publicKey) return error(400, { error: 'ECC requires a public key' });
                const res = service.encryptEcc(body.text, body.publicKey);
                return { method: 'ECC', ...res };
            }
            return error(400, { error: 'Invalid method' });
        } catch (e: any) {
            return error(500, { error: e.message });
        }
    }, {
        body: EncryptBody,
        response: EncryptResponse,
        detail: { summary: "Encrypt Data", tags: ["Operations"] }
    })

    .post("/decrypt", ({ body, service, error }) => {
        try {
            if (body.method === 'AES') {
                if (!body.key) return error(400, { error: 'AES requires a key' });
                const res = service.decryptAes(body.encryptedText, body.key);
                return { method: 'AES', ...res };
            }
            if (body.method === 'RSA') {
                if (!body.privateKey) return error(400, { error: 'RSA requires a private key' });
                const res = service.decryptRsa(body.encryptedText, body.privateKey);
                return { method: 'RSA', ...res };
            }
            if (body.method === 'ECC') {
                if (!body.privateKey) return error(400, { error: 'ECC requires a private key' });
                const res = service.decryptEcc(body.encryptedText, body.privateKey);
                return { method: 'ECC', ...res };
            }
            return error(400, { error: 'Invalid method' });
        } catch (e: any) {
            return error(500, { error: e.message });
        }
    }, {
        body: DecryptBody,
        response: DecryptResponse,
        detail: { summary: "Decrypt Data", tags: ["Operations"] }
    })

    .get("/health", () => ({ status: "healthy" }));

app.listen(config.port || 3000);
console.log(`🦊 API running at ${app.server?.hostname}:${app.server?.port}`);