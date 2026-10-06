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
app.use((req, res, next) => {
  console.log(`[${req.method}] ${req.url}`);
  next();
});

// --- MIDDLEWARE AUTENTIKASI (Satpam Token) ---
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      status: 'failed',
      message: 'Missing authentication',
    });
  }

  const token = authHeader.split(' ')[1];
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

// --- MIDDLEWARE VALIDASI DATA JOI ---
const validate = (schema) => (req, res, next) => {
  const { error } = schema.validate(req.body);
  if (error) {
    return res.status(400).json({
      status: 'failed',
      message: error.details[0].message,
    });
  }
  next();
};

// ==========================================
// 1. ENDPOINT USERS
// ==========================================

// Register User
app.post('/users', async (req, res) => {
  try {
    const schema = Joi.object({
      name: Joi.string().required(),
      email: Joi.string().email().required(),
      password: Joi.string().min(6).required(),
      role: Joi.string().optional(),
    }).unknown(true);

    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({
        status: 'failed',
        message: error.details[0].message,
      });
    }

    const { name, email, password, role = 'user' } = req.body;

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
      text: 'INSERT INTO users(id, fullname, email, password, role, created_at, updated_at) VALUES($1, $2, $3, $4, $5, $6, $7) RETURNING id',
      values: [id, name, email, hashedPassword, role, createdAt, createdAt],
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

// Get User by ID
app.get('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const query = {
      text: 'SELECT id, fullname AS name, email FROM users WHERE id = $1',
      values: [id],
    };
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'User tidak ditemukan',
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        id: result.rows[0].id,
        name: result.rows[0].name,
        email: result.rows[0].email,
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

// ==========================================
// 2. ENDPOINT AUTHENTICATIONS
// ==========================================

// Login
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

// Refresh Token
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

    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_KEY);
    } catch (err) {
      return res.status(400).json({
        status: 'failed',
        message: 'Refresh token tidak valid',
      });
    }

    const checkToken = await pool.query('SELECT token FROM authentications WHERE token = $1', [refreshToken]);
    if (checkToken.rows.length === 0) {
      return res.status(400).json({
        status: 'failed',
        message: 'Refresh token tidak ditemukan di database',
      });
    }

    const accessToken = jwt.sign({ id: decoded.id }, process.env.ACCESS_TOKEN_KEY, { expiresIn: '3h' });

    res.status(200).json({
      status: 'success',
      data: {
        accessToken,
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

// Logout
app.delete('/authentications', verifyToken, async (req, res) => {
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

    try {
      jwt.verify(refreshToken, process.env.REFRESH_TOKEN_KEY);
    } catch (err) {
      return res.status(400).json({
        status: 'failed',
        message: 'Refresh token tidak valid',
      });
    }

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

// ==========================================
// 3. ENDPOINT COMPANIES
// ==========================================

const companySchema = Joi.object({
  name: Joi.string().required(),
  location: Joi.string().required(),
  description: Joi.string().required(),
});

// Create Company
app.post('/companies', verifyToken, async (req, res) => {
  try {
    const { error } = companySchema.validate(req.body);
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

// Get All Companies
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

// Get Company by ID
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
      data: result.rows[0],
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});

// Update Company
app.put('/companies/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    const checkCompany = await pool.query('SELECT * FROM companies WHERE id = $1', [id]);
    if (checkCompany.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Perusahaan tidak ditemukan',
      });
    }

    const updateCompanySchema = Joi.object({
      name: Joi.string().optional(),
      location: Joi.string().optional(),
      description: Joi.string().optional(),
    });

    const { error } = updateCompanySchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        status: 'failed',
        message: error.details[0].message,
      });
    }

    const current = checkCompany.rows[0];
    const name = req.body.name !== undefined ? req.body.name : current.name;
    const location = req.body.location !== undefined ? req.body.location : current.location;
    const description = req.body.description !== undefined ? req.body.description : current.description;
    const updatedAt = new Date().toISOString();

    const query = {
      text: 'UPDATE companies SET name = $1, location = $2, description = $3, updated_at = $4 WHERE id = $5 RETURNING id',
      values: [name, location, description, updatedAt, id],
    };

    await pool.query(query);

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

// Delete Company
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

// ==========================================
// 4. ENDPOINT CATEGORIES
// ==========================================

const categorySchema = Joi.object({
  name: Joi.string().required(),
});

// Create Category
app.post('/categories', verifyToken, async (req, res) => {
  try {
    const { error } = categorySchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        status: 'failed',
        message: error.details[0].message,
      });
    }

    const { name } = req.body;
    const id = `category-${crypto.randomUUID()}`;
    const createdAt = new Date().toISOString();

    const query = {
      text: 'INSERT INTO categories(id, name, created_at, updated_at) VALUES($1, $2, $3, $4) RETURNING id',
      values: [id, name, createdAt, createdAt],
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

// Get All Categories
app.get('/categories', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM categories');
    res.status(200).json({
      status: 'success',
      data: {
        categories: result.rows,
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

// Get Category by ID
app.get('/categories/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT * FROM categories WHERE id = $1', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Kategori tidak ditemukan',
      });
    }

    res.status(200).json({
      status: 'success',
      data: result.rows[0],
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});

// Update Category
app.put('/categories/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    const checkCategory = await pool.query('SELECT * FROM categories WHERE id = $1', [id]);
    if (checkCategory.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Kategori tidak ditemukan',
      });
    }

    const { error } = categorySchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        status: 'failed',
        message: error.details[0].message,
      });
    }

    const { name } = req.body;
    const updatedAt = new Date().toISOString();

    const query = {
      text: 'UPDATE categories SET name = $1, updated_at = $2 WHERE id = $3 RETURNING id',
      values: [name, updatedAt, id],
    };
    await pool.query(query);

    res.status(200).json({
      status: 'success',
      message: 'Kategori berhasil diperbarui',
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});

// Delete Category
app.delete('/categories/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM categories WHERE id = $1 RETURNING id', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Kategori tidak ditemukan',
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'Kategori berhasil dihapus',
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});

// ==========================================
// 5. ENDPOINT JOBS
// ==========================================

const jobSchema = Joi.object({
  company_id: Joi.string().required(),
  category_id: Joi.string().required(),
  title: Joi.string().required(),
  description: Joi.string().required(),
  job_type: Joi.string().required(),
  experience_level: Joi.string().required(),
  location_type: Joi.string().required(),
  location_city: Joi.string().allow(null, '').optional(),
  salary_min: Joi.number().allow(null).optional(),
  salary_max: Joi.number().allow(null).optional(),
  is_salary_visible: Joi.boolean().optional(),
  status: Joi.string().required(),
}).unknown(true);

// Create Job
app.post('/jobs', verifyToken, async (req, res) => {
  try {
    const { error } = jobSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        status: 'failed',
        message: error.details[0].message,
      });
    }

    const {
      company_id,
      category_id,
      title,
      description,
      job_type,
      experience_level,
      location_type,
      location_city,
      salary_min,
      salary_max,
      is_salary_visible,
      status,
    } = req.body;

    const checkCompany = await pool.query('SELECT id FROM companies WHERE id = $1', [company_id]);
    const checkCategory = await pool.query('SELECT id FROM categories WHERE id = $1', [category_id]);

    if (checkCompany.rows.length === 0 || checkCategory.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Company atau Category tidak ditemukan',
      });
    }

    const id = `job-${crypto.randomUUID()}`;
    const createdAt = new Date().toISOString();

    const finalLocationCity = location_city !== undefined ? location_city : '';
    const finalSalaryMin = salary_min !== undefined && salary_min !== null ? salary_min : 0;
    const finalSalaryMax = salary_max !== undefined && salary_max !== null ? salary_max : 0;
    const finalIsSalaryVisible = is_salary_visible !== undefined && is_salary_visible !== null ? is_salary_visible : false;

    const query = {
      text: `INSERT INTO jobs(
        id, company_id, category_id, title, description, job_type, experience_level,
        location_type, location_city, salary_min, salary_max, is_salary_visible, status,
        created_at, updated_at
      ) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) RETURNING id`,
      values: [
        id,
        company_id,
        category_id,
        title,
        description,
        job_type,
        experience_level,
        location_type,
        finalLocationCity,
        finalSalaryMin,
        finalSalaryMax,
        finalIsSalaryVisible,
        status,
        createdAt,
        createdAt,
      ],
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

// Get All Jobs (Search by title & company-name, with company_name join)
app.get('/jobs', async (req, res) => {
  try {
    const { title, 'company-name': companyNameKebab, company_name } = req.query;
    const companyFilter = (companyNameKebab || company_name || '').trim();
    const titleFilter = (title || '').trim();

    let queryText = `
      SELECT jobs.*, companies.name AS company_name
      FROM jobs
      LEFT JOIN companies ON jobs.company_id = companies.id
    `;
    const conditions = [];
    const values = [];

    if (titleFilter) {
      values.push(`%${titleFilter}%`);
      conditions.push(`jobs.title ILIKE $${values.length}`);
    }

    if (companyFilter) {
      values.push(`%${companyFilter}%`);
      conditions.push(`companies.name ILIKE $${values.length}`);
    }

    if (conditions.length > 0) {
      queryText += ' WHERE ' + conditions.join(' AND ');
    }

    const result = await pool.query(queryText, values);
    res.status(200).json({
      status: 'success',
      data: {
        jobs: result.rows,
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

// Get Jobs by Company ID
app.get('/jobs/company/:companyId', async (req, res) => {
  try {
    const { companyId } = req.params;
    const query = {
      text: `SELECT jobs.*, companies.name AS company_name
             FROM jobs
             LEFT JOIN companies ON jobs.company_id = companies.id
             WHERE jobs.company_id = $1`,
      values: [companyId],
    };
    const result = await pool.query(query);
    res.status(200).json({
      status: 'success',
      data: {
        jobs: result.rows,
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

// Get Jobs by Category ID
app.get('/jobs/category/:categoryId', async (req, res) => {
  try {
    const { categoryId } = req.params;
    const query = {
      text: `SELECT jobs.*, companies.name AS company_name
             FROM jobs
             LEFT JOIN companies ON jobs.company_id = companies.id
             WHERE jobs.category_id = $1`,
      values: [categoryId],
    };
    const result = await pool.query(query);
    res.status(200).json({
      status: 'success',
      data: {
        jobs: result.rows,
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

// Get Job by ID
app.get('/jobs/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const query = {
      text: `SELECT jobs.*, companies.name AS company_name
             FROM jobs
             LEFT JOIN companies ON jobs.company_id = companies.id
             WHERE jobs.id = $1`,
      values: [id],
    };
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Pekerjaan tidak ditemukan',
      });
    }

    res.status(200).json({
      status: 'success',
      data: result.rows[0],
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});

// Update Job
app.put('/jobs/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    const checkJob = await pool.query('SELECT * FROM jobs WHERE id = $1', [id]);
    if (checkJob.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Pekerjaan tidak ditemukan',
      });
    }

    const { error } = jobSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        status: 'failed',
        message: error.details[0].message,
      });
    }

    const {
      company_id,
      category_id,
      title,
      description,
      job_type,
      experience_level,
      location_type,
      location_city,
      salary_min,
      salary_max,
      is_salary_visible,
      status,
    } = req.body;
    const updatedAt = new Date().toISOString();

    const finalLocationCity = location_city !== undefined ? location_city : '';
    const finalSalaryMin = salary_min !== undefined && salary_min !== null ? salary_min : 0;
    const finalSalaryMax = salary_max !== undefined && salary_max !== null ? salary_max : 0;
    const finalIsSalaryVisible = is_salary_visible !== undefined && is_salary_visible !== null ? is_salary_visible : false;

    const query = {
      text: `UPDATE jobs SET
        company_id = $1, category_id = $2, title = $3, description = $4,
        job_type = $5, experience_level = $6, location_type = $7, location_city = $8,
        salary_min = $9, salary_max = $10, is_salary_visible = $11, status = $12,
        updated_at = $13 WHERE id = $14 RETURNING id`,
      values: [
        company_id,
        category_id,
        title,
        description,
        job_type,
        experience_level,
        location_type,
        finalLocationCity,
        finalSalaryMin,
        finalSalaryMax,
        finalIsSalaryVisible,
        status,
        updatedAt,
        id,
      ],
    };

    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Pekerjaan tidak ditemukan',
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'Pekerjaan berhasil diperbarui',
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});

// Delete Job
app.delete('/jobs/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM jobs WHERE id = $1 RETURNING id', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Pekerjaan tidak ditemukan',
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'Pekerjaan berhasil dihapus',
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});

// ==========================================
// 6. ENDPOINT APPLICATIONS (Semua Dilindungi verifyToken)
// ==========================================

const applicationSchema = Joi.object({
  user_id: Joi.string().required(),
  job_id: Joi.string().required(),
  status: Joi.string().default('pending').optional(),
}).unknown(true);

// Apply for Job
app.post('/applications', verifyToken, async (req, res) => {
  try {
    const { error } = applicationSchema.validate(req.body);
    if (error) {
      return res.status(400).json({
        status: 'failed',
        message: error.details[0].message,
      });
    }

    const { user_id, job_id, status = 'pending' } = req.body;

    const checkUser = await pool.query('SELECT id FROM users WHERE id = $1', [user_id]);
    const checkJob = await pool.query('SELECT id FROM jobs WHERE id = $1', [job_id]);

    if (checkUser.rows.length === 0 || checkJob.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'User atau Job tidak ditemukan',
      });
    }

    const id = `application-${crypto.randomUUID()}`;
    const createdAt = new Date().toISOString();

    const query = {
      text: 'INSERT INTO applications(id, user_id, job_id, status, created_at, updated_at) VALUES($1, $2, $3, $4, $5, $6) RETURNING id',
      values: [id, user_id, job_id, status, createdAt, createdAt],
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

// Get All Applications
app.get('/applications', verifyToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM applications');
    res.status(200).json({
      status: 'success',
      data: {
        applications: result.rows,
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

// Get Application by ID
app.get('/applications/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT * FROM applications WHERE id = $1', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Application tidak ditemukan',
      });
    }

    res.status(200).json({
      status: 'success',
      data: result.rows[0],
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});

// Get Applications by User ID
app.get('/applications/user/:userId', verifyToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const result = await pool.query('SELECT * FROM applications WHERE user_id = $1', [userId]);
    res.status(200).json({
      status: 'success',
      data: {
        applications: result.rows,
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

// Get Applications by Job ID
app.get('/applications/job/:jobId', verifyToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    const result = await pool.query('SELECT * FROM applications WHERE job_id = $1', [jobId]);
    res.status(200).json({
      status: 'success',
      data: {
        applications: result.rows,
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

// Update Application Status
app.put('/applications/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;

    const checkApp = await pool.query('SELECT * FROM applications WHERE id = $1', [id]);
    if (checkApp.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Application tidak ditemukan',
      });
    }

    const schema = Joi.object({ status: Joi.string().required() }).unknown(true);

    const { error } = schema.validate(req.body);
    if (error) {
      return res.status(400).json({
        status: 'failed',
        message: error.details[0].message,
      });
    }

    const { status } = req.body;
    const updatedAt = new Date().toISOString();

    const query = {
      text: 'UPDATE applications SET status = $1, updated_at = $2 WHERE id = $3 RETURNING id',
      values: [status, updatedAt, id],
    };
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Application tidak ditemukan',
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'Application berhasil diperbarui',
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});

// Delete Application
app.delete('/applications/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM applications WHERE id = $1 RETURNING id', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Application tidak ditemukan',
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'Application berhasil dihapus',
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});

// ==========================================
// 7. ENDPOINT BOOKMARKS (Sesuai Rute Kontrak Dicoding)
// ==========================================

// Add Bookmark: POST /jobs/:jobId/bookmark
app.post('/jobs/:jobId/bookmark', verifyToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    const userId = req.user.id;

    const checkJob = await pool.query('SELECT id FROM jobs WHERE id = $1', [jobId]);
    if (checkJob.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Pekerjaan tidak ditemukan',
      });
    }

    const checkExisting = await pool.query('SELECT id FROM bookmarks WHERE user_id = $1 AND job_id = $2', [userId, jobId]);
    if (checkExisting.rows.length > 0) {
      return res.status(201).json({
        status: 'success',
        data: {
          id: checkExisting.rows[0].id,
        },
      });
    }

    const id = `bookmark-${crypto.randomUUID()}`;
    const createdAt = new Date().toISOString();

    const query = {
      text: 'INSERT INTO bookmarks(id, user_id, job_id, created_at, updated_at) VALUES($1, $2, $3, $4, $5) RETURNING id',
      values: [id, userId, jobId, createdAt, createdAt],
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

// Get All Bookmarks of Current User: GET /bookmarks
app.get('/bookmarks', verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const result = await pool.query('SELECT * FROM bookmarks WHERE user_id = $1', [userId]);

    res.status(200).json({
      status: 'success',
      data: {
        bookmarks: result.rows,
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

// Get Bookmark by ID: GET /jobs/:jobId/bookmark/:bookmarkId
app.get('/jobs/:jobId/bookmark/:bookmarkId', verifyToken, async (req, res) => {
  try {
    const { bookmarkId } = req.params;
    const result = await pool.query('SELECT * FROM bookmarks WHERE id = $1', [bookmarkId]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Bookmark tidak ditemukan',
      });
    }

    res.status(200).json({
      status: 'success',
      data: result.rows[0],
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});

// Delete Bookmark: DELETE /jobs/:jobId/bookmark
app.delete('/jobs/:jobId/bookmark', verifyToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    const userId = req.user.id;

    await pool.query('DELETE FROM bookmarks WHERE user_id = $1 AND job_id = $2', [userId, jobId]);

    res.status(200).json({
      status: 'success',
      message: 'Bookmark berhasil dihapus',
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});

// --- ENDPOINT BOOKMARKS TAMBAHAN (Direct CRUD) ---

// Create Bookmark: POST /bookmarks
app.post('/bookmarks', verifyToken, async (req, res) => {
  try {
    const { job_id, user_id } = req.body;
    const finalUserId = user_id || req.user.id;

    if (!job_id) {
      return res.status(400).json({
        status: 'failed',
        message: 'job_id wajib diisi',
      });
    }

    const checkJob = await pool.query('SELECT id FROM jobs WHERE id = $1', [job_id]);
    if (checkJob.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Pekerjaan tidak ditemukan',
      });
    }

    const checkExisting = await pool.query('SELECT id FROM bookmarks WHERE user_id = $1 AND job_id = $2', [finalUserId, job_id]);
    if (checkExisting.rows.length > 0) {
      return res.status(201).json({
        status: 'success',
        data: { id: checkExisting.rows[0].id },
      });
    }

    const id = `bookmark-${crypto.randomUUID()}`;
    const createdAt = new Date().toISOString();
    const query = {
      text: 'INSERT INTO bookmarks(id, user_id, job_id, created_at, updated_at) VALUES($1, $2, $3, $4, $5) RETURNING id',
      values: [id, finalUserId, job_id, createdAt, createdAt],
    };
    const result = await pool.query(query);

    res.status(201).json({
      status: 'success',
      data: { id: result.rows[0].id },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});

// Get Bookmark by ID: GET /bookmarks/:id
app.get('/bookmarks/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT * FROM bookmarks WHERE id = $1', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Bookmark tidak ditemukan',
      });
    }

    res.status(200).json({
      status: 'success',
      data: result.rows[0],
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});

// Get Bookmarks by User ID: GET /bookmarks/user/:userId
app.get('/bookmarks/user/:userId', verifyToken, async (req, res) => {
  try {
    const { userId } = req.params;
    const result = await pool.query('SELECT * FROM bookmarks WHERE user_id = $1', [userId]);

    res.status(200).json({
      status: 'success',
      data: {
        bookmarks: result.rows,
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

// Get Bookmarks by Job ID: GET /bookmarks/job/:jobId
app.get('/bookmarks/job/:jobId', verifyToken, async (req, res) => {
  try {
    const { jobId } = req.params;
    const result = await pool.query('SELECT * FROM bookmarks WHERE job_id = $1', [jobId]);

    res.status(200).json({
      status: 'success',
      data: {
        bookmarks: result.rows,
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

// Delete Bookmark by ID: DELETE /bookmarks/:id
app.delete('/bookmarks/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM bookmarks WHERE id = $1 RETURNING id', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'Bookmark tidak ditemukan',
      });
    }

    res.status(200).json({
      status: 'success',
      message: 'Bookmark berhasil dihapus',
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: 'error',
      message: 'Terjadi kegagalan pada server kami',
    });
  }
});

// ==========================================
// 8. ENDPOINT OPSIONAL (PROFILE)
// ==========================================

// Get Profile
app.get('/profile', verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const query = {
      text: "SELECT id, fullname AS name, email, COALESCE(role, 'user') AS role FROM users WHERE id = $1",
      values: [userId],
    };
    const result = await pool.query(query);

    if (result.rows.length === 0) {
      return res.status(404).json({
        status: 'failed',
        message: 'User tidak ditemukan',
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        id: result.rows[0].id,
        name: result.rows[0].name,
        email: result.rows[0].email,
        role: result.rows[0].role || 'user',
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

// Get Profile Applications
app.get('/profile/applications', verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const result = await pool.query('SELECT * FROM applications WHERE user_id = $1', [userId]);

    res.status(200).json({
      status: 'success',
      data: {
        applications: result.rows,
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

// Get Profile Bookmarks
app.get('/profile/bookmarks', verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const result = await pool.query('SELECT * FROM bookmarks WHERE user_id = $1', [userId]);

    res.status(200).json({
      status: 'success',
      data: {
        bookmarks: result.rows,
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

// Fallback 404 handler
app.use((req, res) => {
  res.status(404).json({
    status: 'failed',
    message: 'Resource tidak ditemukan',
  });
});

// --- MIDDLEWARE ERROR HANDLING (4 arguments) ---
app.use((err, req, res, next) => {
  console.error(err.stack || err);
  res.status(500).json({
    status: 'error',
    message: 'Terjadi kegagalan pada server kami',
  });
});

app.listen(port, () => {
  console.log(`Server berjalan pada http://${host}:${port}`);
});