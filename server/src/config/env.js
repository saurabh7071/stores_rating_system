import dotenv from 'dotenv';

dotenv.config({ path: './.env' });

const requiredVars = [
    "PORT",
    "PGPORT",
    "PGHOST",
    "PGUSER",
    "PGDATABASE",
    "PGPASSWORD",
]

requiredVars.forEach((varName) => {
    if(!process.env[varName]) {
        console.error(`Error: Missing required environment variable ${varName}`);
        process.exit(1);
    }
})

export const config = {
    port: process.env.PORT || 8080,
    env: process.env.NODE_ENV || 'development',
    pg: {
        host: process.env.PGHOST,
        user: process.env.PGUSER,
        database: process.env.PGDATABASE,
        password: process.env.PGPASSWORD,
        port: Number(process.env.PGPORT),
        max: Number(process.env.PG_MAX|| 10),
        idleTimeoutMillis: Number(process.env.PG_IDLE_TIMEOUT || 30000),
        connectionTimeoutMillis: Number(process.env.PG_CONNECTION_TIMEOUT || 2000),
    },
    jwtSecret: process.env.JWT_ACCESS_SECRET,
    jwtExpiresIn: process.env.JWT_ACCESS_EXPIRY,
    jwtRefreshSecret: process.env.JWT_REFRESH_SECRET,
    jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRY,

    adminEmail: process.env.ADMIN_EMAIL,
    adminPassword: process.env.ADMIN_PASSWORD,

};
