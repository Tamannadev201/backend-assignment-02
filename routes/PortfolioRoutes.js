const express = require("express");
const { createPortfolio, getAllPortfolios, updatePortfolio, deletePortfolio } = require("../controllers/portfolioController");
const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();
router.post("/", authMiddleware, createPortfolio);
router.get("/", getAllPortfolios);
router.put("/:id", authMiddleware, updatePortfolio);
router.delete("/:id", authMiddleware, deletePortfolio);

module.exports = router;
