const { Sequelize } = require('sequelize');
require('dotenv').config();

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'mysql',
  logging: false,
  define: {
    timestamps: true,
    underscored: true
  }
});

module.exports = sequelize;
