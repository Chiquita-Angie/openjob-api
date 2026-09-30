exports.up = (pgm) => {
  // Jaga-jaga kalau sebelumnya udah pernah bikin, kita drop dulu
  pgm.dropTable('jobs', { ifExists: true, cascade: true });
  
  pgm.createTable('jobs', {
    id: { type: 'VARCHAR(50)', primaryKey: true },
    company_id: { type: 'VARCHAR(50)', notNull: true, references: '"companies"', onDelete: 'CASCADE' },
    category_id: { type: 'VARCHAR(50)', notNull: true, references: '"categories"', onDelete: 'CASCADE' },
    title: { type: 'TEXT', notNull: true },
    description: { type: 'TEXT', notNull: true },
    job_type: { type: 'TEXT', notNull: true },
    experience_level: { type: 'TEXT', notNull: true },
    location_type: { type: 'TEXT', notNull: true },
    location_city: { type: 'TEXT', notNull: true },
    salary_min: { type: 'INTEGER', notNull: true },
    salary_max: { type: 'INTEGER', notNull: true },
    is_salary_visible: { type: 'BOOLEAN', notNull: true },
    status: { type: 'TEXT', notNull: true },
    created_at: { type: 'TEXT', notNull: true },
    updated_at: { type: 'TEXT', notNull: true },
  });
};

exports.down = (pgm) => {
  pgm.dropTable('jobs');
};