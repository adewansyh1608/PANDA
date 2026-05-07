const express = require('express');
const router = express.Router();
const { ScanHistory, sequelize } = require('../models');

router.get('/dashboard', async (req, res) => {
    try {
        const stats = await ScanHistory.findAll({
            attributes: [
                'status',
                [sequelize.fn('COUNT', sequelize.col('id')), 'count']
            ],
            group: ['status']
        });
        
        const recentScans = await ScanHistory.findAll({
            limit: 5,
            order: [['scanned_at', 'DESC']]
        });

        res.json({ stats, recentScans });
    } catch (err) {
        res.status(500).json({ error: 'Failed to load dashboard data' });
    }
});

module.exports = router;
