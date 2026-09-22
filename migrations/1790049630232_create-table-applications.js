/* eslint-disable camelcase */
exports.shorthands = undefined;

exports.up = pgm => {
  pgm.createTable('applications', {
    id: { type: 'VARCHAR(50)', primaryKey: true },
    user_id: {
      type: 'VARCHAR(50)',
      notNull: true,
      references: 'users',
      onDelete: 'CASCADE'
    },
    job_id: {
      type: 'VARCHAR(50)',
      notNull: true,
      references: 'jobs',
      onDelete: 'CASCADE'
    },
    status: { 
      type: 'VARCHAR(50)', 
      notNull: true,
      default: 'pending'
    },
    created_at: { type: 'TEXT', notNull: true },
    updated_at: { type: 'TEXT', notNull: true }
  });
};

exports.down = pgm => {
  pgm.dropTable('applications');
};