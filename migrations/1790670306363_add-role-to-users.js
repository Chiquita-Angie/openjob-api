exports.up = (pgm) => {
  pgm.addColumn('users', {
    role: {
      type: 'VARCHAR(50)',
      notNull: false,
      default: 'user',
    },
  });
};

exports.down = (pgm) => {
  pgm.dropColumn('users', 'role');
};
