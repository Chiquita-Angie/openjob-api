exports.up = (pgm) => {
  pgm.alterColumn('jobs', 'location_city', { notNull: false });
  pgm.alterColumn('jobs', 'salary_min', { notNull: false });
  pgm.alterColumn('jobs', 'salary_max', { notNull: false });
  pgm.alterColumn('jobs', 'is_salary_visible', { notNull: false });
};

exports.down = (pgm) => {
  pgm.alterColumn('jobs', 'location_city', { notNull: true });
  pgm.alterColumn('jobs', 'salary_min', { notNull: true });
  pgm.alterColumn('jobs', 'salary_max', { notNull: true });
  pgm.alterColumn('jobs', 'is_salary_visible', { notNull: true });
};




