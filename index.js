require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const Joi = require('joi');
const jwt = require('jsonwebtoken');
const pool = require('./db');

const app = express();
const host = process.env.HOST || 'localhost';
const port = process.env.PORT || 3000;

app.use(express.json());

// --- ENDPOINT REGISTER USER ---
app.post('/users', async (req, res) => {
  try {
    // 1. Validasi disesuaikan sama payload Dicoding
    const schema = Joi.object({
      name: Joi.string().required(),
      email: Joi.string().email().required(),
      password: Joi.string().min(6).required(),
      role: Joi.string().optional() // Biar Joi ga kaget ada data role
    }).unknown(true); // Mengizinkan field ekstra yang gak kita definisikan

    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({
        status: 'fail',
        message: error.details[0].message,
      });
    }

    const { name, email, password } = req.body;

    // 2. Cek email udah dipakai atau belum
    const checkEmail = await pool.query('SELECT email FROM users WHERE email = $1', [email]);
    if (checkEmail.rows.length > 0) {
      return res.status(400).json({
        status: 'fail',
        message: 'Email sudah digunakan',
      });
    }

    // 3. Siapin data buat disimpan
    const id = `user-${crypto.randomUUID()}`;
    const hashedPassword = await bcrypt.hash(password, 10);
    const createdAt = new Date().toISOString();
    
    // 4. Simpan ke database (name dari Postman dimasukin ke fullname di DB)
    const query = {
      text: 'INSERT INTO users(id, fullname, email, password, created_at, updated_at) VALUES($1, $2, $3, $4, $5, $6) RETURNING id',
      values: [id, name, email, hashedPassword, createdAt, createdAt],
    };

    const result = await pool.query(query);

    // 5. Kasih respon sukses
    res.status(201).json({
      status: 'success',
      data: {
        userId: result.rows[0].id,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});
// --- ENDPOINT GET USER BY ID (Sesuai Kriteria 2) ---
app.get('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Kita panggil fullname sebagai name biar cocok sama tes Dicoding
    const query = {
      text: 'SELECT id, fullname, email FROM users WHERE id = $1',
      values: [id]
    };
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({
        status: 'fail',
        message: 'User tidak ditemukan'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        user: result.rows[0]
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami'
    });
  }
});

// --- ENDPOINT LOGIN / AUTHENTICATIONS (Sesuai Kriteria 2) ---
app.post('/authentications', async (req, res) => {
  try {
    const schema = Joi.object({
      email: Joi.string().email().required(),
      password: Joi.string().required(),
    });

    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({
        status: 'fail',
        message: error.details[0].message,
      });
    }

    const { email, password } = req.body;

    const query = {
      text: 'SELECT id, password FROM users WHERE email = $1',
      values: [email],
    };
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(401).json({
        status: 'fail',
        message: 'Kredensial yang Anda berikan salah',
      });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({
        status: 'fail',
        message: 'Kredensial yang Anda berikan salah',
      });
    }

    // Bikin Token JWT (Access Token 3 jam sesuai Kriteria Advanced Dicoding)
    const accessToken = jwt.sign({ id: user.id }, process.env.ACCESS_TOKEN_KEY, { expiresIn: '3h' });
    const refreshToken = jwt.sign({ id: user.id }, process.env.REFRESH_TOKEN_KEY);

    // Simpan refresh token ke database
    await pool.query('INSERT INTO authentications(token) VALUES($1)', [refreshToken]);

    res.status(201).json({
      status: 'success',
      data: {
        accessToken,
        refreshToken,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});
app.listen(port, host, () => {
  console.log(`Server berjalan pada http://${host}:${port}`);
});