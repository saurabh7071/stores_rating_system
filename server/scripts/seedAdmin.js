import bcrypt from "bcrypt";
import { pool } from "../src/config/db.js";
import { config } from "../src/config/env.js";

const ADMIN_EMAIL = config.adminEmail;
const ADMIN_PASSWORD = config.adminPassword;
const SALT_ROUNDS = 12;

(async () => {
    try {
        const checkAdminQuery = `
            SELECT id, email 
            FROM users 
            WHERE role = 'ADMIN'
            LIMIT 1;
        `;

        const existingAdmin = await pool.query(checkAdminQuery);

        if (existingAdmin.rowCount > 0) {
            console.log("System Administrator already exists. Seeding skipped.");
            process.exit(0);
        }

        const password_hash = bcrypt.hash(ADMIN_PASSWORD, SALT_ROUNDS);

        const insertAdminQuery = `
            INSERT INTO users (name, email, password_hash, address, role, created_at, updated_at, is_active)
            VALUES ($1, $2, $3, $4, $5, NOW(), NOW(), true)
            RETURNING id, name, email, role, created_at;
    `;

        const values = [
            "System Administrator",
            ADMIN_EMAIL.toLowerCase(),
            password_hash,
            "Admin Office Headquarters",
            "ADMIN"
        ];

        const result = await pool.query(insertAdminQuery, values);
        const admin = result.rows[0];

        console.log("System Administrator created successfully:");
        process.exit(0);

    } catch (error) {
        console.error("Error seeding admin:", error);
        process.exit(1);
    }
})();


// to run -> node scripts/seed-admin.js
