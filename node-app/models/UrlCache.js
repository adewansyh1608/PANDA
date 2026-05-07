const { DataTypes } = require('sequelize');
const sequelize = require('../config/database');

const UrlCache = sequelize.define('UrlCache', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  url: {
    type: DataTypes.TEXT,
    allowNull: false,
    unique: true
  },
  url_hash: {
    type: DataTypes.STRING(64),
    allowNull: false,
    unique: true
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
  last_checked: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  },
  expires_at: {
    type: DataTypes.DATE,
    allowNull: false
  },
  hit_count: {
    type: DataTypes.INTEGER,
    defaultValue: 1
  }
}, {
  tableName: 'url_cache'
});

module.exports = UrlCache;
