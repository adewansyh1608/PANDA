const express = require('express');
const router = express.Router();
const scanController = require('../controllers/scanController');
const { scanLimiter } = require('../middlewares/rateLimiter');

router.post('/scan', scanLimiter, scanController.scanURL);
router.get('/history', scanController.getHistory);

module.exports = router;
