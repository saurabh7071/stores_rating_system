import bcrypt from "bcrypt";
import { pool } from "../config/db.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";

const SALT_ROUNDS = 12;

const strongPasswordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&*!()_+\-={}\[\]|:;"'<>,.?/~`]).{8,}$/;

const storeOwnerUpdatePassword = asyncHandler(async (req, res) => {
    const userId = req.user?.sub;
    const role = req.user?.role;

    const { oldPassword, newPassword } = req.body;

    await new Promise(resolve => setTimeout(resolve, 120));

    if (!oldPassword || !newPassword) {
        throw new ApiError(400, "oldPassword and newPassword are required");
    }

    if (!strongPasswordRegex.test(newPassword)) {
        throw new ApiError(
            400,
            "New password must include at least 1 lowercase letter, 1 uppercase letter, 1 number, 1 special character, and must be at least 8 characters long."
        );
    }

    if (role !== "STORE_OWNER") {
        throw new ApiError(403, "Only store owners can update their password");
    }

    const sql = `
        SELECT id, password_hash, is_active
        FROM users
        WHERE id = $1 AND role = 'STORE_OWNER'
        LIMIT 1;
    `;
    const result = await pool.query(sql, [userId]);

    if (result.rowCount === 0) {
        throw new ApiError(404, "Store owner not found");
    }

    const owner = result.rows[0];

    if (!owner.is_active) {
        throw new ApiError(403, "Your account is inactive. Contact admin.");
    }

    const isMatch = await bcrypt.compare(oldPassword, owner.password_hash);
    if (!isMatch) {
        throw new ApiError(401, "Old password is incorrect");
    }

    const isSamePassword = await bcrypt.compare(newPassword, owner.password_hash);
    if (isSamePassword) {
        throw new ApiError(400, "New password cannot match your current password");
    }

    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

    const updateSql = `
        UPDATE users
        SET password_hash = $1, updated_at = NOW()
        WHERE id = $2;
    `;
    await pool.query(updateSql, [hashedPassword, userId]);

    return res
        .status(200)
        .json(new ApiResponse(200, null, "Password updated successfully"));
});

const getStoreRatingsUsers = asyncHandler(async (req, res) => {
    const ownerId = req.user.id;
    const storeId = req.params.storeId;

    if (!validator.isUUID(storeId)) {
        throw new ApiError(400, "Invalid store ID format");
    }

    const storeCheck = await pool.query(
        `SELECT id, owner_id, is_active 
        FROM stores 
        WHERE id = $1`,
        [storeId]
    );

    if (storeCheck.rowCount === 0) {
        throw new ApiError(404, "Store not found");
    }

    const store = storeCheck.rows[0];

    if (!store.is_active) {
        throw new ApiError(403, "Store is disabled. Contact admin.");
    }

    if (store.owner_id !== ownerId) {
        throw new ApiError(403, "You are not authorized to access this store");
    }

    const ratingListQuery = `
        SELECT 
            u.id AS user_id,
            u.name,
            u.email,
            r.rating_value,
            r.created_at
        FROM ratings r
        JOIN users u ON u.id = r.user_id
        WHERE r.store_id = $1
        ORDER BY r.created_at DESC;
    `;

    const { rows } = await pool.query(ratingListQuery, [storeId]);

    return res
        .status(200)
        .json(new ApiResponse(200, rows, "Users who rated your store fetched successfully"));
});

const getStoreAverageRating = asyncHandler(async (req, res) => {
    const ownerId = req.user.id;
    const storeId = req.params.storeId;

    if (!validator.isUUID(storeId)) {
        throw new ApiError(400, "Invalid store ID format");
    }

    const storeCheck = await pool.query(
        `SELECT id, owner_id, is_active 
        FROM stores
        WHERE id = $1`,
        [storeId]
    );

    if (storeCheck.rowCount === 0) {
        throw new ApiError(404, "Store not found");
    }

    const store = storeCheck.rows[0];

    if (!store.is_active) {
        throw new ApiError(403, "Store is disabled");
    }

    if (store.owner_id !== ownerId) {
        throw new ApiError(403, "You do not own this store");
    }

    const avgQuery = `
        SELECT 
            COALESCE(AVG(rating_value), 0)::numeric(3,2) AS average_rating,
            COUNT(*) AS total_ratings
        FROM ratings
        WHERE store_id = $1;
    `;

    const { rows } = await pool.query(avgQuery, [storeId]);

    return res
        .status(200)
        .json(new ApiResponse(200, rows[0], "Average rating fetched successfully"));
});

const logout = asyncHandler(async (req, res) => {
    let token = null;

    const authHeader = req.headers.authorization || "";
    if (authHeader.startsWith("Bearer ")) {
        token = authHeader.split(" ")[1];
    }

    if (!token && req.cookies?.token) {
        token = req.cookies.token;
    }

    if (!token) {
        throw new ApiError(400, "No token found to logout");
    }

    let decoded = null;
    try {
        decoded = jwt.verify(token, config.jwtSecret, { algorithms: ["HS256"] });
    } catch (err) {
        decoded = null;
    }

    try {
        await pool.query(
            `INSERT INTO token_blacklist (token, expires_at)
             VALUES ($1, NOW() + INTERVAL '2 hours')`,
            [token]
        );
    } catch (err) {
        console.error("Blacklist insertion failed (not fatal):", err.message);
    }

    res.clearCookie("token", {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
    });

    return res.status(200).json(
        new ApiResponse(200, null, "Logged out successfully. Token cleared.")
    );
});

export {
    storeOwnerUpdatePassword,
    getStoreRatingsUsers,
    getStoreAverageRating,
    logout
};
