const crypto = require('crypto');
const axios = require('axios');
const { UrlCache, ScanHistory } = require('../models');

exports.scanURL = async (req, res) => {
    try {
        const { url } = req.body;
        if (!url) {
            return res.status(400).json({ error: 'URL is required' });
        }

        // 1. Create SHA256 hash of the URL for fast lookup
        const urlHash = crypto.createHash('sha256').update(url).digest('hex');

        // 2. Lookup in cache
        let cacheEntry = await UrlCache.findOne({ where: { url_hash: urlHash } });
        let source = 'model';
        let result = null;

        const now = new Date();

        // 3. Check if exists and not expired
        if (cacheEntry && new Date(cacheEntry.expires_at) > now) {
            source = 'cache';
            
            // Increment hit count
            await cacheEntry.increment('hit_count');
            
            result = {
                label: cacheEntry.label,
                status: cacheEntry.status,
                confidence: cacheEntry.confidence,
                url: cacheEntry.url,
                hit_count: cacheEntry.hit_count + 1
            };
        } else {
            // 4. Call FastAPI to predict
            try {
                const response = await axios.post(`${process.env.PYTHON_API_URL}/predict`, { url });
                result = response.data;
                result.hit_count = 1; // First time scan

                // Update or Insert into Cache (24 hours TTL)
                const expiresAt = new Date();
                expiresAt.setHours(expiresAt.getHours() + 24);

                await UrlCache.upsert({
                    url: url,
                    url_hash: urlHash,
                    label: result.label,
                    status: result.status,
                    confidence: result.confidence,
                    last_checked: now,
                    expires_at: expiresAt,
                    hit_count: 1
                });
            } catch (apiError) {
                console.error('FastAPI Error:', apiError.message);
                return res.status(500).json({ error: 'Failed to connect to ML service' });
            }
        }

        // 5. Save to scan_history
        await ScanHistory.create({
            url: url,
            label: result.label,
            status: result.status,
            confidence: result.confidence,
            source: source,
            scanned_at: now
        });

        // 6. Return response
        return res.json({
            ...result,
            source,
            scanned_at: now
        });

    } catch (err) {
        console.error('Scan Error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
};

exports.getHistory = async (req, res) => {
    try {
        const history = await ScanHistory.findAll({
            order: [['scanned_at', 'DESC']]
        });
        res.json(history);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch history' });
    }
};
