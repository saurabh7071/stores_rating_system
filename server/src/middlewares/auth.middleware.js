import jwt from "jsonwebtoken";
import { ApiError } from "../utils/ApiError.js";
import { pool } from "../config/db.js";
import { config } from "../config/env.js";

export const requireAuth = async (req, res, next) => {
    try {
        const authHeader = (req.headers.authorization || "").split(" ");
        let token = null;

        if (authHeader.length === 2 && authHeader[0] === "Bearer") {
            token = authHeader[1];
        } else if (req.cookies && req.cookies.token) {
            token = req.cookies.token;
        }

        if (!token) {
            throw new ApiError(401, "Authentication required");
        }

        let payload;
        try {
            payload = jwt.verify(token, config.jwtSecret, { algorithms: ["HS256"] });
        } catch (err) {
            throw new ApiError(401, "Invalid or expired token");
        }

        // fetch user minimal state to ensure active and role etc
        const { rows } = await pool.query("SELECT id, role, is_active FROM users WHERE id = $1", [payload.sub]);
        if (rows.length === 0) throw new ApiError(401, "Authentication required");

        const user = rows[0];
        if (!user.is_active) throw new ApiError(403, "Account disabled");

        // attach to request
        req.user = { id: user.id, role: user.role };

        next();
    } catch (err) {
        next(err);
    }
};


export const requireRole = (role) => (req, res, next) => {
    if (!req.user) return next(new ApiError(401, "Authentication required"));
    if (req.user.role !== role) return next(new ApiError(403, "Insufficient permissions"));
    return next();
};

export const requireAdmin = (req, res, next) => {
    if (!req.user || req.user.role !== "ADMIN") {
        throw new ApiError(403, "Admin access required");
    }
    next();
};

export const requireStoreOwner = (req, res, next) => {
    if (!req.user || req.user.role !== "STORE_OWNER") {
        throw new ApiError(403, "Store owner access required");
    }
    next();
};

