exports.up = (pgm) => {
  // Bom tabel lama beserta relasinya
  pgm.dropTable('companies', { ifExists: true, cascade: true });
  
  // Bangun ulang sesuai format Dicoding
  pgm.createTable('companies', {
    id: { type: 'VARCHAR(50)', primaryKey: true },
    name: { type: 'TEXT', notNull: true },
    location: { type: 'TEXT', notNull: true },
    description: { type: 'TEXT', notNull: true },
    created_at: { type: 'TEXT', notNull: true },
    updated_at: { type: 'TEXT', notNull: true },
  });
};

exports.down = (pgm) => {
  pgm.dropTable('companies');
};