/* eslint-disable camelcase */
exports.shorthands = undefined;

exports.up = pgm => {
  pgm.createTable('jobs', {
    id: { type: 'VARCHAR(50)', primaryKey: true },
    title: { type: 'VARCHAR(255)', notNull: true },
    description: { type: 'TEXT', notNull: true },
    company_id: {
      type: 'VARCHAR(50)',
      notNull: true,
      references: 'companies',
      onDelete: 'CASCADE'
    },
    category_id: {
      type: 'VARCHAR(50)',
      notNull: true,
      references: 'categories',
      onDelete: 'CASCADE'
    },
    created_at: { type: 'TEXT', notNull: true },
    updated_at: { type: 'TEXT', notNull: true }
  });
};

exports.down = pgm => {
  pgm.dropTable('jobs');
};