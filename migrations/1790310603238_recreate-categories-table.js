exports.up = (pgm) => {
  pgm.dropTable('categories', { ifExists: true, cascade: true });
  pgm.createTable('categories', {
    id: { type: 'VARCHAR(50)', primaryKey: true },
    name: { type: 'TEXT', notNull: true },
    created_at: { type: 'TEXT', notNull: true },
    updated_at: { type: 'TEXT', notNull: true },
  });
};

exports.down = (pgm) => {
  pgm.dropTable('categories');
};