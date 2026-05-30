/**
 * STANDALONE FUNCTIONAL TEST FLOW
 * Run this script to test all the features of your live Phishing Detector Website!
 * 
 * Usage:
 *   1. Make sure your MySQL database is running and configured in node-app/.env
 *   2. Make sure your FastAPI server is running (port 8000)
 *   3. Start your node server: npm run dev (port 3000)
 *   4. In another terminal, run: node test-flow.js
 */

const axios = require('axios');
require('dotenv').config();

const PORT = process.env.PORT || 3000;
const BASE_URL = `http://localhost:${PORT}`;

// Colors for beautiful terminal output
const colors = {
    reset: '\x1b[0m',
    bright: '\x1b[1m',
    green: '\x1b[32m',
    red: '\x1b[31m',
    yellow: '\x1b[33m',
    cyan: '\x1b[36m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    bgGreen: '\x1b[42m',
    bgRed: '\x1b[48;5;88m'
};

function printHeader(title) {
    console.log(`\n${colors.bright}${colors.cyan}================================================================================`);
    console.log(`  ${title.toUpperCase()}`);
    console.log(`================================================================================${colors.reset}`);
}

function printResult(name, success, info = '') {
    if (success) {
        console.log(`  [${colors.green}PASS${colors.reset}] ${colors.bright}${name}${colors.reset} ${info ? `- ${colors.cyan}${info}${colors.reset}` : ''}`);
    } else {
        console.log(`  [${colors.red}FAIL${colors.reset}] ${colors.bright}${name}${colors.reset} ${info ? `- ${colors.red}${info}${colors.reset}` : ''}`);
    }
}

async function runTests() {
    printHeader('Starting Phishing Detector Website Functional Tests');
    console.log(`Target URL: ${colors.yellow}${BASE_URL}${colors.reset}\n`);

    let passedTests = 0;
    let totalTests = 0;

    const trackResult = (name, success, info) => {
        totalTests++;
        if (success) passedTests++;
        printResult(name, success, info);
    };

    // ==========================================
    // PHASE 1: Pages EJS / Frontend Load Checks
    // ==========================================
    printHeader('Phase 1: HTML & EJS Views Loading Checks');

    const pages = [
        { path: '/', name: 'Home page (index)' },
        { path: '/scan', name: 'Scan Page' },
        { path: '/history', name: 'History Page' },
        { path: '/dashboard', name: 'Dashboard Page' },
        { path: '/admin', name: 'Admin Control Page' },
        { path: '/about', name: 'About Page' }
    ];

    for (const page of pages) {
        try {
            const res = await axios.get(`${BASE_URL}${page.path}`);
            const isHTML = res.headers['content-type'].includes('text/html');
            const hasTitle = res.data.toLowerCase().includes('<title>');
            trackResult(
                page.name, 
                res.status === 200 && isHTML && hasTitle, 
                `Status: ${res.status}, Type: text/html`
            );
        } catch (err) {
            trackResult(page.name, false, err.message);
        }
    }

    // ==========================================
    // PHASE 2: API Endpoints Checks
    // ==========================================
    printHeader('Phase 2: API Route Operations');

    // 2.1 Get Stats
    try {
        const res = await axios.get(`${BASE_URL}/api/admin/admin/stats`);
        const validKeys = 'totalScans' in res.data && 'phishingFound' in res.data;
        trackResult(
            'GET /api/admin/admin/stats (Admin Statistics)',
            res.status === 200 && validKeys,
            `Total Scans: ${res.data.totalScans}, Phishing Found: ${res.data.phishingFound}`
        );
    } catch (err) {
        trackResult('GET /api/admin/admin/stats', false, err.message);
    }

    // 2.2 Get Dashboard Stats
    try {
        const res = await axios.get(`${BASE_URL}/api/dashboard/dashboard`);
        const hasStats = Array.isArray(res.data.stats) && Array.isArray(res.data.recentScans);
        trackResult(
            'GET /api/dashboard/dashboard (Dashboard Analytics)',
            res.status === 200 && hasStats,
            `Stats count: ${res.data.stats.length}, Recent scans count: ${res.data.recentScans.length}`
        );
    } catch (err) {
        trackResult('GET /api/dashboard/dashboard', false, err.message);
    }

    // 2.3 URL Scan Endpoint Tests (Crucial Core Logic!)
    const testUrls = [
        { url: 'https://www.google.com', expected: 'safe', label: 'Google (Expected Safe)' },
        { url: 'http://phishing-test-site.com', expected: 'phishing', label: 'Phishing Sim (Expected Phishing)' }
    ];

    printHeader('Phase 3: Live ML Phishing Scan (Requires FastAPI up)');
    console.log(`${colors.yellow}Info: This test contacts FastAPI. Ensure FastAPI at 8000 & MySQL are running.${colors.reset}\n`);

    for (const test of testUrls) {
        try {
            console.log(`  Scanning URL: ${colors.magenta}${test.url}${colors.reset}...`);
            const res = await axios.post(`${BASE_URL}/api/scan/scan`, { url: test.url });
            
            const hasCorrectStructure = 'status' in res.data && 'confidence' in res.data && 'source' in res.data;
            const success = res.status === 200 && hasCorrectStructure;
            
            let extraInfo = '';
            if (success) {
                extraInfo = `Status: ${res.data.status}, Confidence: ${(res.data.confidence * 100).toFixed(1)}%, Source: ${res.data.source}`;
            }
            
            trackResult(
                `POST /api/scan/scan -> ${test.label}`,
                success,
                extraInfo || `Status Code: ${res.status}`
            );
        } catch (err) {
            let errorMsg = err.message;
            if (err.response && err.response.data && err.response.data.error) {
                errorMsg += ` (${err.response.data.error})`;
            }
            trackResult(
                `POST /api/scan/scan -> ${test.label}`,
                false,
                `Error: ${errorMsg}`
            );
        }
    }

    // 2.4 History Fetch Checks
    try {
        const res = await axios.get(`${BASE_URL}/api/scan/history`);
        const isArray = Array.isArray(res.data);
        trackResult(
            'GET /api/scan/history (Retrieve Scanned History)',
            res.status === 200 && isArray,
            `Found ${isArray ? res.data.length : 0} logs inside history database`
        );
    } catch (err) {
        trackResult('GET /api/scan/history', false, err.message);
    }

    // ==========================================
    // SUMMARY
    // ==========================================
    console.log(`\n${colors.bright}${colors.cyan}================================================================================`);
    console.log(`  TEST RUN SUMMARY`);
    console.log(`================================================================================${colors.reset}`);
    
    const percentage = ((passedTests / totalTests) * 100).toFixed(1);
    console.log(`  Total Tests Run: ${colors.bright}${totalTests}${colors.reset}`);
    console.log(`  Passed Tests:    ${colors.green}${colors.bright}${passedTests}${colors.reset}`);
    console.log(`  Failed Tests:    ${passedTests === totalTests ? colors.green : colors.red}${colors.bright}${totalTests - passedTests}${colors.reset}`);
    console.log(`  Success Rate:    ${percentage === '100.0' ? colors.green : colors.yellow}${colors.bright}${percentage}%${colors.reset}\n`);

    if (passedTests === totalTests) {
        console.log(`  ${colors.bgGreen}${colors.bright}  SUCCESS: All components of your Phishing Website are running perfectly!  ${colors.reset}\n`);
    } else {
        console.log(`  ${colors.bgRed}${colors.bright}  WARNING: Some test items failed. Check if services (FastAPI/MySQL) are fully up and active.  ${colors.reset}\n`);
    }
}

runTests();
