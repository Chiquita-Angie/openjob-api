/* eslint-disable camelcase */
exports.shorthands = undefined;

exports.up = pgm => {
  pgm.createTable('bookmarks', {
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
    created_at: { type: 'TEXT', notNull: true },
    updated_at: { type: 'TEXT', notNull: true }
  });

  // Biar 1 user cuma bisa nge-bookmark 1 job yang sama sekali aja
  pgm.addConstraint('bookmarks', 'unique_user_id_and_job_id', {
    unique: ['user_id', 'job_id']
  });
};

exports.down = pgm => {
  pgm.dropTable('bookmarks');
};