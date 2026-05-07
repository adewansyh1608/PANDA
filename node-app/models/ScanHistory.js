const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const ScanHistory = sequelize.define('ScanHistory', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },

  url: {
    type: DataTypes.TEXT,
    allowNull: false
  },
  label: {
    type: DataTypes.INTEGER,
    allowNull: false
  },
  status: {
    type: DataTypes.STRING,
    allowNull: false
  },
  confidence: {
    type: DataTypes.FLOAT,
    allowNull: false
  },
  source: {
    type: DataTypes.ENUM('cache', 'model'),
    allowNull: false
  },
  scanned_at: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  }
}, {
  tableName: 'scan_histories'
});

module.exports = ScanHistory;
