import { Router } from "express";
import { 
    storeOwnerUpdatePassword,
    getStoreRatingsUsers,
    getStoreAverageRating ,
    logout
} from "../controllers/storeOwner.controller.js";
import { requireStoreOwner } from "../middlewares/auth.middleware.js";

const router = Router();

router.route("/updatePassword").post(requireStoreOwner, storeOwnerUpdatePassword);
router.route("/:storeId/ratings/users").get(requireStoreOwner, getStoreRatingsUsers);
router.route("/:storeId/ratings/average").get(requireStoreOwner, getStoreAverageRating);
router.route("/logout").post(requireStoreOwner, logout);

export default router;