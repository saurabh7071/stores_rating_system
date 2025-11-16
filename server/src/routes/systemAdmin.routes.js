import { Router } from "express";
import { 
    adminLogin, 
    adminCreateUser, 
    adminCreateStore,
    adminGetAllStores,
    adminGetAllUsers 
} from "../controllers/systemAdmin.controller.js";
import { requireAdmin } from "../middlewares/auth.middleware.js";

const router = Router();

router.route("/adminlogin").post(adminLogin);
router.route("/createUser").post(requireAdmin, adminCreateUser);
router.route("/createStore").post(requireAdmin, adminCreateStore);
router.route("/stores").get(requireAdmin, adminGetAllStores);
router.route("/users").get(requireAdmin, adminGetAllUsers);

export default router;