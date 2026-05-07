const express = require('express');
const router = express.Router();
const { ScanHistory, UrlCache, sequelize } = require('../models');

router.get('/admin/stats', async (req, res) => {
    try {
        const totalScans = await ScanHistory.count();
        const phishingFound = await ScanHistory.count({ where: { status: 'phishing' } });
        const cacheHitRate = await ScanHistory.count({ where: { source: 'cache' } });

        res.json({
            totalUsers: 0,
            totalScans,
            phishingFound,
            cacheHitRate: totalScans > 0 ? (cacheHitRate / totalScans * 100).toFixed(2) : 0
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch admin stats' });
    }
});

module.exports = router;
