export interface AppConfig {
  port: number;
  db: {
    host: string;
    port: number;
    user: string;
    password: string;
    database: string;
  };
}

export const config: AppConfig = {
  port: Number(process.env.PORT || 3000),
  db: {
    host: process.env.DB_HOST || "db",
    port: Number(process.env.DB_PORT || 5432),
    user: process.env.DB_USER || "encryption",
    password: process.env.DB_PASSWORD || "encryption_password",
    database: process.env.DB_NAME || "encryption_db"
  }
};
