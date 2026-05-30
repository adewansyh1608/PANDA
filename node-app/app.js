const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const path = require('path');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const dotenv = require('dotenv');
const { syncDB } = require('./models');

// Load environment variables
dotenv.config();

const app = express();

// Middleware
app.use(morgan('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// EJS Setup
app.use(expressLayouts);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('layout', 'layouts/main');

// Routes
const scanRoutes = require('./routes/scan');
const dashboardRoutes = require('./routes/dashboard');
const adminRoutes = require('./routes/admin');

app.use('/api/scan', scanRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/admin', adminRoutes);

// View Routes
app.get('/', (req, res) => res.render('pages/index', { title: 'Home' }));
app.get('/dashboard', (req, res) => res.render('pages/dashboard', { title: 'Dashboard' }));
app.get('/scan', (req, res) => res.render('pages/scan', { title: 'Scan' }));
app.get('/history', (req, res) => res.render('pages/history', { title: 'History' }));
app.get('/admin', (req, res) => res.render('pages/admin', { title: 'Admin' }));
app.get('/about', (req, res) => res.render('pages/about', { title: 'About Us' }));

// Database Sync & Start Server
const PORT = process.env.PORT || 3000;

syncDB().then(() => {
    app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
    });
});

module.exports = app;
