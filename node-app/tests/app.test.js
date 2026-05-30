const request = require('supertest');
const axios = require('axios');

// Mock axios
jest.mock('axios');

// Mock Sequelize models
const mockUrlCache = {
  findOne: jest.fn(),
  upsert: jest.fn(),
  increment: jest.fn(),
};

const mockScanHistory = {
  create: jest.fn(),
  findAll: jest.fn(),
  count: jest.fn(),
};

const mockSequelize = {
  fn: jest.fn((fnName, col) => fnName),
  col: jest.fn(col => col),
};

jest.mock('../models', () => ({
  UrlCache: mockUrlCache,
  ScanHistory: mockScanHistory,
  sequelize: mockSequelize,
  syncDB: jest.fn().mockResolvedValue(true),
}));

// Mock database config to avoid real DB connections in tests
jest.mock('../config/database', () => ({
  authenticate: jest.fn().mockResolvedValue(true),
  sync: jest.fn().mockResolvedValue(true),
}));

const app = require('../app');

describe('Phishing Detector Express API and Web Pages', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('Frontend Page Routes', () => {
    test('GET / should render the index page', async () => {
      const res = await request(app).get('/');
      expect(res.statusCode).toBe(200);
      expect(res.text).toContain('Home');
    });

    test('GET /scan should render scan page', async () => {
      const res = await request(app).get('/scan');
      expect(res.statusCode).toBe(200);
      expect(res.text).toContain('Scan');
    });

    test('GET /history should render history page', async () => {
      const res = await request(app).get('/history');
      expect(res.statusCode).toBe(200);
      expect(res.text).toContain('History');
    });

    test('GET /dashboard should render dashboard page', async () => {
      const res = await request(app).get('/dashboard');
      expect(res.statusCode).toBe(200);
      expect(res.text).toContain('Dashboard');
    });

    test('GET /admin should render admin page', async () => {
      const res = await request(app).get('/admin');
      expect(res.statusCode).toBe(200);
      expect(res.text).toContain('Admin');
    });

    test('GET /about should render about page', async () => {
      const res = await request(app).get('/about');
      expect(res.statusCode).toBe(200);
      expect(res.text).toContain('About Us');
    });
  });

  describe('API Endpoints', () => {
    test('GET /api/scan/history should retrieve scan history', async () => {
      const mockHistory = [
        { id: 1, url: 'https://test.com', status: 'safe', confidence: 0.9, scanned_at: new Date() }
      ];
      mockScanHistory.findAll.mockResolvedValue(mockHistory);

      const res = await request(app).get('/api/scan/history');
      expect(res.statusCode).toBe(200);
      expect(res.body).toEqual(expect.any(Array));
      expect(res.body[0].url).toBe('https://test.com');
      expect(mockScanHistory.findAll).toHaveBeenCalled();
    });

    test('POST /api/scan/scan should scan URL and fetch from model when cache misses', async () => {
      mockUrlCache.findOne.mockResolvedValue(null); // Cache miss
      
      const mockPredictResponse = {
        data: {
          label: 1,
          status: 'safe',
          confidence: 0.98
        }
      };
      axios.post.mockResolvedValue(mockPredictResponse);
      
      mockUrlCache.upsert.mockResolvedValue([true, false]);
      mockScanHistory.create.mockResolvedValue({});

      const res = await request(app)
        .post('/api/scan/scan')
        .send({ url: 'https://safe-site.com' });

      expect(res.statusCode).toBe(200);
      expect(res.body.status).toBe('safe');
      expect(res.body.source).toBe('model');
      expect(axios.post).toHaveBeenCalled();
      expect(mockUrlCache.upsert).toHaveBeenCalled();
      expect(mockScanHistory.create).toHaveBeenCalled();
    });

    test('POST /api/scan/scan should hit cache when URL is cached and active', async () => {
      const mockCacheEntry = {
        url: 'https://cached-site.com',
        label: 1,
        status: 'safe',
        confidence: 0.99,
        expires_at: new Date(Date.now() + 100000), // Active cache
        hit_count: 5,
        increment: jest.fn().mockResolvedValue(true)
      };
      
      mockUrlCache.findOne.mockResolvedValue(mockCacheEntry);
      mockScanHistory.create.mockResolvedValue({});

      const res = await request(app)
        .post('/api/scan/scan')
        .send({ url: 'https://cached-site.com' });

      expect(res.statusCode).toBe(200);
      expect(res.body.status).toBe('safe');
      expect(res.body.source).toBe('cache');
      expect(axios.post).not.toHaveBeenCalled(); // Fast lookup, no API call
      expect(mockCacheEntry.increment).toHaveBeenCalledWith('hit_count');
      expect(mockScanHistory.create).toHaveBeenCalled();
    });

    test('GET /api/admin/admin/stats should retrieve stats', async () => {
      mockScanHistory.count
        .mockResolvedValueOnce(10)  // totalScans
        .mockResolvedValueOnce(3)   // phishingFound
        .mockResolvedValueOnce(4);  // cacheHitRate

      const res = await request(app).get('/api/admin/admin/stats');
      expect(res.statusCode).toBe(200);
      expect(res.body.totalScans).toBe(10);
      expect(res.body.phishingFound).toBe(3);
      expect(res.body.cacheHitRate).toBe('40.00');
    });

    test('GET /api/dashboard/dashboard should retrieve dashboard overview stats', async () => {
      mockScanHistory.findAll
        .mockResolvedValueOnce([{ status: 'safe', count: 7 }, { status: 'phishing', count: 3 }]) // stats
        .mockResolvedValueOnce([{ id: 1, url: 'https://test.com', status: 'safe', scanned_at: new Date() }]); // recentScans

      const res = await request(app).get('/api/dashboard/dashboard');
      expect(res.statusCode).toBe(200);
      expect(res.body.stats).toBeDefined();
      expect(res.body.recentScans).toBeDefined();
      expect(res.body.stats.length).toBe(2);
      expect(res.body.recentScans.length).toBe(1);
    });
  });
});
