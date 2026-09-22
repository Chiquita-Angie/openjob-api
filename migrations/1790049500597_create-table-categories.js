/* eslint-disable camelcase */
exports.shorthands = undefined;

exports.up = pgm => {
  pgm.createTable('categories', {
    id: { type: 'VARCHAR(50)', primaryKey: true },
    name: { type: 'VARCHAR(255)', notNull: true },
    created_at: { type: 'TEXT', notNull: true },
    updated_at: { type: 'TEXT', notNull: true }
  });
};

exports.down = pgm => {
  pgm.dropTable('categories');
};