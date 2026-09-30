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

// --- MIDDLEWARE AUTENTIKASI (Satpam Token) ---
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({
      status: 'failed',
      message: 'Missing authentication',
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_KEY);
    req.user = decoded; 
    next(); 
  } catch (error) {
    return res.status(401).json({
      status: 'failed',
      message: 'Token tidak valid',
    });
  }
};

// --- ENDPOINT REGISTER USER ---
app.post('/users', async (req, res) => {
  try {
    const schema = Joi.object({
      name: Joi.string().required(),
      email: Joi.string().email().required(),
      password: Joi.string().min(6).required(),
      role: Joi.string().optional()
    }).unknown(true);

    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({
        status: 'failed',
        message: error.details[0].message,
      });
    }

    const { name, email, password } = req.body;

    const checkEmail = await pool.query('SELECT email FROM users WHERE email = $1', [email]);
    if (checkEmail.rows.length > 0) {
      return res.status(400).json({
        status: 'failed',
        message: 'Email sudah digunakan',
      });
    }

    const id = `user-${crypto.randomUUID()}`;
    const hashedPassword = await bcrypt.hash(password, 10);
    const createdAt = new Date().toISOString();
    
    const query = {
      text: 'INSERT INTO users(id, fullname, email, password, created_at, updated_at) VALUES($1, $2, $3, $4, $5, $6) RETURNING id',
      values: [id, name, email, hashedPassword, createdAt, createdAt],
    };

    const result = await pool.query(query);

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

// --- ENDPOINT GET USER BY ID ---
app.get('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Menyesuaikan balikan fullname menjadi name sesuai kontrak
    const query = {
      text: 'SELECT id, fullname AS name, email FROM users WHERE id = $1',
      values: [id]
    };
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
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

// --- ENDPOINT LOGIN / AUTHENTICATIONS ---
app.post('/authentications', async (req, res) => {
  try {
    const schema = Joi.object({
      email: Joi.string().email().required(),
      password: Joi.string().required(),
    });

    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({
        status: 'failed',
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
        status: 'failed',
        message: 'Kredensial yang Anda berikan salah',
      });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({
        status: 'failed',
        message: 'Kredensial yang Anda berikan salah',
      });
    }

    const accessToken = jwt.sign({ id: user.id }, process.env.ACCESS_TOKEN_KEY, { expiresIn: '3h' });
    const refreshToken = jwt.sign({ id: user.id }, process.env.REFRESH_TOKEN_KEY);

    await pool.query('INSERT INTO authentications(token) VALUES($1)', [refreshToken]);

    // Mengubah status dari 201 menjadi 200 sesuai permintaan reviewer
    res.status(200).json({
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

// --- ENDPOINT PUT /authentications (Refresh Token) ---
app.put('/authentications', async (req, res) => {
  try {
    const schema = Joi.object({
      refreshToken: Joi.string().required(),
    });

    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({
        status: 'failed',
        message: error.details[0].message,
      });
    }

    const { refreshToken } = req.body;

    const checkToken = await pool.query('SELECT token FROM authentications WHERE token = $1', [refreshToken]);
    if (checkToken.rows.length === 0) {
      return res.status(400).json({
        status: 'failed',
        message: 'Refresh token tidak ditemukan di database',
      });
    }

    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_KEY);
    const accessToken = jwt.sign({ id: decoded.id }, process.env.ACCESS_TOKEN_KEY, { expiresIn: '3h' });

    res.status(200).json({
      status: 'success',
      message: 'Access Token berhasil diperbarui',
      data: {
        accessToken,
      },
    });
  } catch (error) {
    return res.status(400).json({
      status: 'failed',
      message: 'Refresh token tidak valid',
    });
  }
});

// --- ENDPOINT DELETE /authentications (Logout) ---
app.delete('/authentications', async (req, res) => {
  try {
    const schema = Joi.object({
      refreshToken: Joi.string().required(),
    });

    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({
        status: 'failed',
        message: error.details[0].message,
      });
    }

    const { refreshToken } = req.body;

    const checkToken = await pool.query('SELECT token FROM authentications WHERE token = $1', [refreshToken]);
    if (checkToken.rows.length === 0) {
      return res.status(400).json({
        status: 'failed',
        message: 'Refresh token tidak ditemukan di database',
      });
    }

    await pool.query('DELETE FROM authentications WHERE token = $1', [refreshToken]);

    res.status(200).json({
      status: 'success',
      message: 'Refresh token berhasil dihapus',
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});

// --- ENDPOINT POST /companies ---
app.post('/companies', verifyToken, async (req, res) => {
  try {
    const schema = Joi.object({
      name: Joi.string().required(),
      location: Joi.string().required(),
      description: Joi.string().required(),
    });

    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({
        status: 'failed',
        message: error.details[0].message,
      });
    }

    const { name, location, description } = req.body;
    
    const id = `company-${crypto.randomUUID()}`;
    const createdAt = new Date().toISOString();

    const query = {
      text: 'INSERT INTO companies(id, name, location, description, created_at, updated_at) VALUES($1, $2, $3, $4, $5, $6) RETURNING id',
      values: [id, name, location, description, createdAt, createdAt],
    };

    const result = await pool.query(query);

    res.status(201).json({
      status: 'success',
      data: {
        id: result.rows[0].id,
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

// --- ENDPOINT GET ALL COMPANIES ---
app.get('/companies', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM companies');
    res.status(200).json({
      status: 'success',
      data: {
        companies: result.rows,
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

// --- ENDPOINT GET COMPANY BY ID ---
app.get('/companies/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT * FROM companies WHERE id = $1', [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Perusahaan tidak ditemukan',
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        company: result.rows[0],
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

// --- ENDPOINT PUT /companies/:id (Update) ---
app.put('/companies/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const schema = Joi.object({
      name: Joi.string().required(),
      location: Joi.string().required(),
      description: Joi.string().required(),
    });

    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({
        status: 'failed',
        message: error.details[0].message,
      });
    }

    const { name, location, description } = req.body;
    const updatedAt = new Date().toISOString();

    const query = {
      text: 'UPDATE companies SET name = $1, location = $2, description = $3, updated_at = $4 WHERE id = $5 RETURNING id',
      values: [name, location, description, updatedAt, id],
    };

    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Perusahaan tidak ditemukan',
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'Perusahaan berhasil diperbarui',
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});

// --- ENDPOINT DELETE /companies/:id ---
app.delete('/companies/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query('DELETE FROM companies WHERE id = $1 RETURNING id', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Perusahaan tidak ditemukan',
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'Perusahaan berhasil dihapus',
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});

// --- ENDPOINT CATEGORIES ---

// 1. POST Add Category
app.post('/categories', verifyToken, async (req, res) => {
  try {
    const schema = Joi.object({ name: Joi.string().required() });
    const { error } = schema.validate(req.body);
    if (error) return res.status(400).json({ status: 'failed', message: error.details[0].message });

    const { name } = req.body;
    const id = `category-${crypto.randomUUID()}`;
    const createdAt = new Date().toISOString();

    const query = {
      text: 'INSERT INTO categories(id, name, created_at, updated_at) VALUES($1, $2, $3, $4) RETURNING id',
      values: [id, name, createdAt, createdAt],
    };
    const result = await pool.query(query);

    res.status(201).json({ status: 'success', data: { id: result.rows[0].id } });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 2. GET All Categories
app.get('/categories', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM categories');
    res.status(200).json({ status: 'success', data: { categories: result.rows } });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 3. GET Category By ID
app.get('/categories/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT * FROM categories WHERE id = $1', [id]);
    
    if (result.rows.length === 0) return res.status(404).json({ status: 'failed', message: 'Kategori tidak ditemukan' });
    res.status(200).json({ status: 'success', data: { category: result.rows[0] } });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 4. PUT Update Category
app.put('/categories/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const schema = Joi.object({ name: Joi.string().required() });
    const { error } = schema.validate(req.body);
    if (error) return res.status(400).json({ status: 'failed', message: error.details[0].message });

    const { name } = req.body;
    const updatedAt = new Date().toISOString();

    const query = {
      text: 'UPDATE categories SET name = $1, updated_at = $2 WHERE id = $3 RETURNING id',
      values: [name, updatedAt, id],
    };
    const result = await pool.query(query);

    if (result.rows.length === 0) return res.status(404).json({ status: 'failed', message: 'Kategori tidak ditemukan' });
    res.status(200).json({ status: 'success', message: 'Kategori berhasil diperbarui' });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 5. DELETE Category
app.delete('/categories/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM categories WHERE id = $1 RETURNING id', [id]);

    if (result.rows.length === 0) return res.status(404).json({ status: 'failed', message: 'Kategori tidak ditemukan' });
    res.status(200).json({ status: 'success', message: 'Kategori berhasil dihapus' });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// --- ENDPOINT JOBS ---

const jobSchema = Joi.object({
  company_id: Joi.string().required(),
  category_id: Joi.string().required(),
  title: Joi.string().required(),
  description: Joi.string().required(),
  job_type: Joi.string().required(),
  experience_level: Joi.string().required(),
  location_type: Joi.string().required(),
  location_city: Joi.string().required(),
  salary_min: Joi.number().required(),
  salary_max: Joi.number().required(),
  is_salary_visible: Joi.boolean().required(),
  status: Joi.string().required()
});

// 1. POST Add Job
app.post('/jobs', verifyToken, async (req, res) => {
  try {
    const { error } = jobSchema.validate(req.body);
    if (error) return res.status(400).json({ status: 'failed', message: error.details[0].message });

    const { company_id, category_id, title, description, job_type, experience_level, location_type, location_city, salary_min, salary_max, is_salary_visible, status } = req.body;
    
    // Cek apakah company dan category ada di database
    const checkCompany = await pool.query('SELECT id FROM companies WHERE id = $1', [company_id]);
    const checkCategory = await pool.query('SELECT id FROM categories WHERE id = $1', [category_id]);
    
    if (checkCompany.rows.length === 0 || checkCategory.rows.length === 0) {
      return res.status(404).json({ status: 'failed', message: 'Company atau Category tidak ditemukan' });
    }

    const id = `job-${crypto.randomUUID()}`;
    const createdAt = new Date().toISOString();

    const query = {
      text: 'INSERT INTO jobs(id, company_id, category_id, title, description, job_type, experience_level, location_type, location_city, salary_min, salary_max, is_salary_visible, status, created_at, updated_at) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) RETURNING id',
      values: [id, company_id, category_id, title, description, job_type, experience_level, location_type, location_city, salary_min, salary_max, is_salary_visible, status, createdAt, createdAt],
    };
    const result = await pool.query(query);

    res.status(201).json({ status: 'success', data: { id: result.rows[0].id } });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 2. GET All Jobs (Dengan filter by company_id & category_id)
app.get('/jobs', async (req, res) => {
  try {
    const { company_id, category_id } = req.query;
    let queryText = 'SELECT * FROM jobs';
    const values = [];

    if (company_id) {
      queryText += ' WHERE company_id = $1';
      values.push(company_id);
    } else if (category_id) {
      queryText += ' WHERE category_id = $1';
      values.push(category_id);
    }

    const result = await pool.query(queryText, values);
    res.status(200).json({ status: 'success', data: { jobs: result.rows } });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// --- ENDPOINT TAMBAHAN JOBS (By Company & Category) ---

// GET Jobs by Company ID
app.get('/jobs/company/:companyId', async (req, res) => {
  try {
    const { companyId } = req.params;
    const result = await pool.query('SELECT * FROM jobs WHERE company_id = $1', [companyId]);
    res.status(200).json({ status: 'success', data: { jobs: result.rows } });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 3. GET Jobs by Category ID
app.get('/jobs/category/:categoryId', async (req, res) => {
  try {
    const { categoryId } = req.params;
    const result = await pool.query('SELECT * FROM jobs WHERE category_id = $1', [categoryId]);
    res.status(200).json({ status: 'success', data: { jobs: result.rows } });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 4. GET Job By ID
app.get('/jobs/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT * FROM jobs WHERE id = $1', [id]);
    
    if (result.rows.length === 0) return res.status(404).json({ status: 'failed', message: 'Pekerjaan tidak ditemukan' });
    res.status(200).json({ status: 'success', data: { job: result.rows[0] } });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 5. PUT Update Job
app.put('/jobs/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = jobSchema.validate(req.body);
    if (error) return res.status(400).json({ status: 'failed', message: error.details[0].message });

    const { company_id, category_id, title, description, job_type, experience_level, location_type, location_city, salary_min, salary_max, is_salary_visible, status } = req.body;
    const updatedAt = new Date().toISOString();

    const query = {
      text: 'UPDATE jobs SET company_id = $1, category_id = $2, title = $3, description = $4, job_type = $5, experience_level = $6, location_type = $7, location_city = $8, salary_min = $9, salary_max = $10, is_salary_visible = $11, status = $12, updated_at = $13 WHERE id = $14 RETURNING id',
      values: [company_id, category_id, title, description, job_type, experience_level, location_type, location_city, salary_min, salary_max, is_salary_visible, status, updatedAt, id],
    };
    const result = await pool.query(query);

    if (result.rows.length === 0) return res.status(404).json({ status: 'failed', message: 'Pekerjaan tidak ditemukan' });
    res.status(200).json({ status: 'success', message: 'Pekerjaan berhasil diperbarui' });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

//6. DELETE Job
app.delete('/jobs/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM jobs WHERE id = $1 RETURNING id', [id]);

    if (result.rows.length === 0) return res.status(404).json({ status: 'failed', message: 'Pekerjaan tidak ditemukan' });
    res.status(200).json({ status: 'success', message: 'Pekerjaan berhasil dihapus' });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// --- ENDPOINT APPLICATIONS ---

const applicationSchema = Joi.object({
  user_id: Joi.string().required(),
  job_id: Joi.string().required(),
  status: Joi.string().required()
});

// 1. POST Add Application
app.post('/applications', verifyToken, async (req, res) => {
  try {
    const { error } = applicationSchema.validate(req.body);
    if (error) return res.status(400).json({ status: 'failed', message: error.details[0].message });

    const { user_id, job_id, status } = req.body;
    
    // Cek apakah user dan job valid
    const checkUser = await pool.query('SELECT id FROM users WHERE id = $1', [user_id]);
    const checkJob = await pool.query('SELECT id FROM jobs WHERE id = $1', [job_id]);
    
    if (checkUser.rows.length === 0 || checkJob.rows.length === 0) {
      return res.status(404).json({ status: 'failed', message: 'User atau Job tidak ditemukan' });
    }

    const id = `application-${crypto.randomUUID()}`;
    const createdAt = new Date().toISOString();

    const query = {
      text: 'INSERT INTO applications(id, user_id, job_id, status, created_at, updated_at) VALUES($1, $2, $3, $4, $5, $6) RETURNING id',
      values: [id, user_id, job_id, status, createdAt, createdAt],
    };
    const result = await pool.query(query);

    res.status(201).json({ status: 'success', data: { id: result.rows[0].id } });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 2. GET All Applications
app.get('/applications', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM applications');
    res.status(200).json({ status: 'success', data: { applications: result.rows } });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 3. GET Application By ID
app.get('/applications/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT * FROM applications WHERE id = $1', [id]);
    
    if (result.rows.length === 0) return res.status(404).json({ status: 'failed', message: 'Application tidak ditemukan' });
    res.status(200).json({ status: 'success', data: { application: result.rows[0] } });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 4. GET Applications by User ID
app.get('/applications/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const result = await pool.query('SELECT * FROM applications WHERE user_id = $1', [userId]);
    res.status(200).json({ status: 'success', data: { applications: result.rows } });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 5. GET Applications by Job ID
app.get('/applications/job/:jobId', async (req, res) => {
  try {
    const { jobId } = req.params;
    const result = await pool.query('SELECT * FROM applications WHERE job_id = $1', [jobId]);
    res.status(200).json({ status: 'success', data: { applications: result.rows } });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 6. PUT Update Application Status
app.put('/applications/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    // Mengizinkan update walau cuma ngirim status
    const schema = Joi.object({ status: Joi.string().required() }).unknown(true);
    
    const { error } = schema.validate(req.body);
    if (error) return res.status(400).json({ status: 'failed', message: error.details[0].message });

    const { status } = req.body;
    const updatedAt = new Date().toISOString();

    const query = {
      text: 'UPDATE applications SET status = $1, updated_at = $2 WHERE id = $3 RETURNING id',
      values: [status, updatedAt, id],
    };
    const result = await pool.query(query);

    if (result.rows.length === 0) return res.status(404).json({ status: 'failed', message: 'Application tidak ditemukan' });
    res.status(200).json({ status: 'success', message: 'Application berhasil diperbarui' });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 7. DELETE Application
app.delete('/applications/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM applications WHERE id = $1 RETURNING id', [id]);

    if (result.rows.length === 0) return res.status(404).json({ status: 'failed', message: 'Application tidak ditemukan' });
    res.status(200).json({ status: 'success', message: 'Application berhasil dihapus' });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// --- ENDPOINT BOOKMARKS ---

const bookmarkSchema = Joi.object({
  user_id: Joi.string().required(),
  job_id: Joi.string().required()
});

// 1. POST Add Bookmark
app.post('/bookmarks', verifyToken, async (req, res) => {
  try {
    const { error } = bookmarkSchema.validate(req.body);
    if (error) return res.status(400).json({ status: 'failed', message: error.details[0].message });

    const { user_id, job_id } = req.body;
    
    // Cek apakah user dan job valid
    const checkUser = await pool.query('SELECT id FROM users WHERE id = $1', [user_id]);
    const checkJob = await pool.query('SELECT id FROM jobs WHERE id = $1', [job_id]);
    
    if (checkUser.rows.length === 0 || checkJob.rows.length === 0) {
      return res.status(404).json({ status: 'failed', message: 'User atau Job tidak ditemukan' });
    }

    const id = `bookmark-${crypto.randomUUID()}`;
    const createdAt = new Date().toISOString();

    const query = {
      text: 'INSERT INTO bookmarks(id, user_id, job_id, created_at, updated_at) VALUES($1, $2, $3, $4, $5) RETURNING id',
      values: [id, user_id, job_id, createdAt, createdAt],
    };
    const result = await pool.query(query);

    res.status(201).json({ status: 'success', data: { id: result.rows[0].id } });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 2. GET All Bookmarks
app.get('/bookmarks', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM bookmarks');
    res.status(200).json({ status: 'success', data: { bookmarks: result.rows } });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 3. GET Bookmark By ID
app.get('/bookmarks/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT * FROM bookmarks WHERE id = $1', [id]);
    
    if (result.rows.length === 0) return res.status(404).json({ status: 'failed', message: 'Bookmark tidak ditemukan' });
    res.status(200).json({ status: 'success', data: { bookmark: result.rows[0] } });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 4. GET Bookmarks by User ID
app.get('/bookmarks/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const result = await pool.query('SELECT * FROM bookmarks WHERE user_id = $1', [userId]);
    res.status(200).json({ status: 'success', data: { bookmarks: result.rows } });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 5. GET Bookmarks by Job ID
app.get('/bookmarks/job/:jobId', async (req, res) => {
  try {
    const { jobId } = req.params;
    const result = await pool.query('SELECT * FROM bookmarks WHERE job_id = $1', [jobId]);
    res.status(200).json({ status: 'success', data: { bookmarks: result.rows } });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 6. PUT Update Bookmark
app.put('/bookmarks/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { error } = bookmarkSchema.validate(req.body);
    if (error) return res.status(400).json({ status: 'failed', message: error.details[0].message });

    const { user_id, job_id } = req.body;
    const updatedAt = new Date().toISOString();

    const query = {
      text: 'UPDATE bookmarks SET user_id = $1, job_id = $2, updated_at = $3 WHERE id = $4 RETURNING id',
      values: [user_id, job_id, updatedAt, id],
    };
    const result = await pool.query(query);

    if (result.rows.length === 0) return res.status(404).json({ status: 'failed', message: 'Bookmark tidak ditemukan' });
    res.status(200).json({ status: 'success', message: 'Bookmark berhasil diperbarui' });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

// 7. DELETE Bookmark
app.delete('/bookmarks/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM bookmarks WHERE id = $1 RETURNING id', [id]);

    if (result.rows.length === 0) return res.status(404).json({ status: 'failed', message: 'Bookmark tidak ditemukan' });
    res.status(200).json({ status: 'success', message: 'Bookmark berhasil dihapus' });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Terjadi kegagalan pada server kami' });
  }
});

app.listen(port, host, () => {
  console.log(`Server berjalan pada http://${host}:${port}`);
});