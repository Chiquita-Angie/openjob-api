/* eslint-disable camelcase */

exports.shorthands = undefined;

exports.up = pgm => {
  pgm.createTable('users', {
    id: {
      type: 'VARCHAR(50)',
      primaryKey: true,
    },
    fullname: {
      type: 'VARCHAR(255)',
      notNull: true,
    },
    email: {
      type: 'VARCHAR(255)',
      notNull: true,
      unique: true, 
    },
    password: {
      type: 'TEXT',
      notNull: true,
    },
    created_at: {
      type: 'TEXT',
      notNull: true,
    },
    updated_at: {
      type: 'TEXT',
      notNull: true,
    }
  });
};

exports.down = pgm => {
  pgm.dropTable('users');
};