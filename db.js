const { Pool } = require('pg');
require('dotenv').config();

// Pool otomatis ngebaca variabel PGUSER, PGPASSWORD, dll dari file .env kamu
const pool = new Pool();

module.exports = pool;