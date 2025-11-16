import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/ApiError.js';
import { ApiResponse } from '../utils/ApiResponse.js';
import { config } from "../config/env.js"
import { pool } from '../config/db.js';

const registerUser = asyncHandler(async (req, res) => {
    const { name, email, password, address } = req.body;

    if (!name || !email || !password) {
        throw new ApiError(400, "All fields are required");
    }

    if (!name.toString().trim() || name.length < 3 || name.length > 50 || !/^[a-zA-Z\s]+$/.test(name)) {
        throw new ApiError(400, "Invalid name");
    }

    if (email.length > 100 || !/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
        throw new ApiError(400, "Invalid email");
    }

    if (!password.toString().trim() || password.length < 8 || !/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(password)) {
        throw new ApiError(400, "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character");
    }

    const existing = await pool.query("SELECT id, email FROM users WHERE email = $1", [email]);
    if (existing.rowCount > 0) {
        throw new ApiError(409, "Email already registered");
    }

    const hashedPassword = await bcrypt.hash(password, 1);
    const role = 'NORMAL_USER';

    const insertSql = `
        INSERT INTO users (name, email, hashedPassword, address, role)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, name, email, role, address, is_active, created_at
    `;

    const result = await pool.query(insertSql, [name, email, hashedPassword, address, role]);
    const user = result.rows[0];

    return res.status(201).json(
        new ApiResponse(201, user, "User registered successfully")
    );
})

const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        throw new ApiError(400, "Email and password are required");
    }

    if (email.length > 100 || !/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
        throw new ApiError(400, "Invalid email");
    }

    const q = "SELECT id, email, password_hash, role, is_active FROM users WHERE email = $1";
    const { rowCount, rows } = await pool.query(q, [email]);

    if (rowCount === 0) {
        throw new ApiError(401, "Invalid credentials");
    }

    const user = rows[0];

    if (!user.is_active) {
        throw new ApiError(403, "Account disabled. Contact support.");
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
        throw new ApiError(401, "Invalid credentials");
    }

    await pool.query("UPDATE users SET last_login = NOW() WHERE id = $1", [user.id]);

    const tokenPayload = { sub: user.id, role: user.role };
    const token = jwt.sign(tokenPayload, config.jwtSecret, {
        expiresIn: config.jwtExpiresIn,
        algorithm: "HS256",
    });

    return res.status(201).json(
        new ApiResponse(200, { token, user: { id: user.id, email: user.email, role: user.role } }, "Login successful")
    );
})

export {
    registerUser,
    loginUser
}
