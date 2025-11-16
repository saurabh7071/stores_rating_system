import bcrypt from "bcrypt";
import { pool } from "../config/db.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";

const emailRegex = /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i;
const nameRegex = /^[A-Za-z ]+$/;
const SALT_ROUNDS = 12;

const adminLogin = asyncHandler(async (req, res) => {
    const email = req.body.email?.toLowerCase().trim();
    const password = req.body.password;

    if (!email || !password) {
        throw new ApiError(400, "Email and password are required");
    }
    if (!emailRegex.test(email)) {
        throw new ApiError(400, "Invalid email format");
    }

    await new Promise(resolve => setTimeout(resolve, 150));

    const query = `
        SELECT id, name, email, password_hash, role, is_active
        FROM users
        WHERE email = $1 AND role = 'ADMIN'
        LIMIT 1;
    `;
    const result = await pool.query(query, [email]);

    if (result.rowCount === 0) {
        throw new ApiError(401, "Invalid email or password");
    }

    const admin = result.rows[0];

    if (!admin.is_active) {
        throw new ApiError(403, "Account disabled. Contact system owner.");
    }

    const isMatch = await bcrypt.compare(password, admin.password_hash);
    if (!isMatch) {
        throw new ApiError(401, "Invalid email or password");
    }

    const tokenPayload = { sub: admin.id, role: admin.role };
    const token = jwt.sign(tokenPayload, config.jwtSecret, {
        expiresIn: config.jwtExpiresIn,
        algorithm: "HS256",
    });

    await pool.query(
        `UPDATE users SET last_login = NOW(), updated_at = NOW() WHERE id = $1`,
        [admin.id]
    );

    return res.status(200).json(
        new ApiResponse(200,
            {
                admin: {
                    id: admin.id,
                    name: admin.name,
                    email: admin.email,
                    role: admin.role,
                },
                token,
            },
            "Admin logged in successfully"
        )
    );
});

const adminCreateUser = asyncHandler(async (req, res) => {
    const name = req.body.name?.trim();
    const email = req.body.email?.toLowerCase().trim();
    const password = req.body.password;
    const address = req.body.address?.trim() || null;
    const role = req.body.role;  

    if (!name || !email || !password || !role) {
        throw new ApiError(400, "name, email, password, and role are required");
    }

    if (!nameRegex.test(name) || name.length < 3 || name.length > 60) {
        throw new ApiError(400, "Invalid name (letters & spaces, 3–60 chars)");
    }

    if (!emailRegex.test(email)) {
        throw new ApiError(400, "Invalid email format");
    }

    if (password.length < 8) {
        throw new ApiError(400, "Password must be at least 8 characters");
    }

    if (!["NORMAL_USER", "STORE_OWNER"].includes(role)) {
        throw new ApiError(400, "Invalid role. Must be NORMAL_USER or STORE_OWNER");
    }

    const existing = await pool.query(
        "SELECT id FROM users WHERE email = $1 LIMIT 1",
        [email]
    );

    if (existing.rowCount > 0) {
        throw new ApiError(409, "Email already registered");
    }

    const password_hash = await bcrypt.hash(password, SALT_ROUNDS);

    const sql = `
        INSERT INTO users (name, email, password_hash, address, role, is_active, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, true, NOW(), NOW())
        RETURNING id, name, email, role, created_at
    `;

    const result = await pool.query(sql, [
        name,
        email,
        password_hash,
        address,
        role
    ]);

    const user = result.rows[0];

    return res
        .status(201)
        .json(new ApiResponse(201, { user }, "User created successfully by admin"));
});

const adminCreateStore = asyncHandler(async (req, res) => {
    const name = req.body.name?.trim();
    const email = req.body.email?.toLowerCase().trim();
    const address = req.body.address?.trim();
    const owner_id = req.body.owner_id;

    await new Promise(resolve => setTimeout(resolve, 100));

    if (!name || !email || !address || !owner_id) {
        throw new ApiError(400, "name, email, address, and owner_id are required");
    }

    if (!nameRegex.test(name) || name.length < 3 || name.length > 120) {
        throw new ApiError(400,"Invalid store name");
    }

    if (!emailRegex.test(email)) {
        throw new ApiError(400, "Invalid store email format");
    }

    if (address.length < 6 || address.length > 400) {
        throw new ApiError(400, "Address must be between 6 and 400 characters");
    }

    const ownerCheckQuery = `
        SELECT id, email, role, is_active
        FROM users
        WHERE id = $1
        LIMIT 1;
    `;
    const ownerResult = await pool.query(ownerCheckQuery, [owner_id]);

    if (ownerResult.rowCount === 0) {
        throw new ApiError(404, "Store owner user does not exist");
    }

    const owner = ownerResult.rows[0];

    if (owner.role !== "STORE_OWNER") {
        throw new ApiError(403,"The user assigned as owner does not have STORE_OWNER role");
    }

    if (!owner.is_active) {
        throw new ApiError(403, "Store owner account is inactive");
    }

    if (owner.email === email) {
        throw new ApiError(
            400,
            "Store email cannot be the same as the store owner's email"
        );
    }

    const emailExists = await pool.query(
        "SELECT id FROM stores WHERE email = $1 LIMIT 1;",
        [email]
    );

    if (emailExists.rowCount > 0) {
        throw new ApiError(409, "Store with this email already exists");
    }

    const insertStoreSQL = `
        INSERT INTO stores (name, email, address, owner_id, is_active, created_at, updated_at)
        VALUES ($1, $2, $3, $4, true, NOW(), NOW())
        RETURNING id, name, email, address, owner_id, created_at;
    `;

    const storeResult = await pool.query(insertStoreSQL, [
        name,
        email,
        address,
        owner_id
    ]);

    const store = storeResult.rows[0];

    return res
        .status(201)
        .json(
            new ApiResponse(
                201,
                { store },
                "Store registered successfully by admin"
            )
        );
});

const adminGetAllStores = asyncHandler(async (req, res) => {
    const limit = Number(req.query.limit) || 20;
    const offset = Number(req.query.offset) || 0;

    await new Promise(resolve => setTimeout(resolve, 80));

    if (limit < 1 || limit > 100) {
        throw new ApiError(400, "Limit must be between 1 and 100");
    }

    const sql = `
        SELECT 
            s.id,
            s.name,
            s.email,
            s.address,
            s.owner_id,

            ROUND(AVG(r.rating_value)::numeric, 2) AS rating,

            COUNT(r.id) AS total_ratings,

            s.created_at,
            s.is_active

        FROM stores s
        LEFT JOIN ratings r ON s.id = r.store_id
        GROUP BY s.id
        ORDER BY s.created_at DESC
        LIMIT $1 OFFSET $2;
    `;

    const result = await pool.query(sql, [limit, offset]);

    return res
        .status(200)
        .json(new ApiResponse(200, { stores: result.rows }, "Stores fetched successfully"));
});

const adminGetAllUsers = asyncHandler(async (req, res) => {

    const limit = Number(req.query.limit) || 20;
    const offset = Number(req.query.offset) || 0;

    await new Promise(resolve => setTimeout(resolve, 80));

    if (limit < 1 || limit > 100) {
        throw new ApiError(400, "Limit must be between 1 and 100");
    }

    /**
     * We join:
     *  - users
     *  - stores (LEFT JOIN → only if the user is a store owner)
     *  - ratings (LEFT JOIN → rating of that store)
     */
    const sql = `
        SELECT
            u.id,
            u.name,
            u.email,
            u.address,
            u.role,
            u.is_active,
            u.created_at,

            -- Store details (NULL for non-store-owners)
            s.id AS store_id,
            s.name AS store_name,

            -- Store rating calculations
            ROUND(AVG(r.rating_value)::numeric, 2) AS store_rating,
            COUNT(r.id) AS store_total_ratings

        FROM users u
        LEFT JOIN stores s 
            ON u.id = s.owner_id

        LEFT JOIN ratings r 
            ON s.id = r.store_id
        
        WHERE u.role IN ('ADMIN', 'NORMAL_USER', 'STORE_OWNER')
        GROUP BY u.id, s.id
        ORDER BY u.created_at DESC
        LIMIT $1 OFFSET $2;
    `;

    const result = await pool.query(sql, [limit, offset]);

    return res
        .status(200)
        .json(
            new ApiResponse(
                200,
                { users: result.rows },
                "Users fetched successfully"
            )
        );
});


export {
    adminLogin,
    adminCreateUser,
    adminCreateStore,
    adminGetAllStores,
    adminGetAllUsers
}