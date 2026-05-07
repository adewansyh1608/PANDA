const rateLimit = require('express-rate-limit');

const scanLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 100, // Limit each IP to 100 scan requests per windowMs
    message: {
        error: 'Too many scans from this IP, please try again after an hour'
    },
    standardHeaders: true,
    legacyHeaders: false,
});

module.exports = { scanLimiter };
