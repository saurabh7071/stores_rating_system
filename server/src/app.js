import express from "express"
import cors from "cors"
import helmet from "helmet";
import rateLimit from "express-rate-limit";

const app = express()

app.use(helmet());
app.use(cors({origin: true, credentials: true}));
app.use(express.json({limit: "16kb"}));
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: "Too many requests from this IP, please try again after 15 minutes"
}))

app.get("/health", (req, res) =>{
    res.status(200).json({
        status: "OK",
        timestamp: new Date().toISOString()
    });
})

// route import
import userRoutes from "./routes/user.routes.js";
import systemAdminRoutes from "./routes/systemAdmin.routes.js";
import storeOwnerRoutes from "./routes/storeOwner.routes.js";
import { errorHandler } from "./utils/errorHandler.js";

// route declaration
app.use("/api/v1/user", userRoutes);
app.use("/api/v1/admin", systemAdminRoutes);
app.use("/api/v1/storeOwner", storeOwnerRoutes);
app.use(errorHandler);

export {app};