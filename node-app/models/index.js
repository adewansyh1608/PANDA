const sequelize = require('../config/database');
const UrlCache = require('./UrlCache');
const ScanHistory = require('./ScanHistory');

const db = {
  sequelize,
  UrlCache,
  ScanHistory
};

// Sync database function
const syncDB = async (force = false) => {
  try {
    await sequelize.sync({ force });
    console.log('Database synced successfully');
  } catch (error) {
    console.error('Error syncing database:', error);
  }
};

module.exports = {
  ...db,
  syncDB
};
