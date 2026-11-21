const { execSync } = require('node:child_process');

module.exports = async () => {
  const url =
    process.env.TEST_DATABASE_URL ??
    'postgresql://oauth:oauth@localhost:5432/oauth_test';
  execSync('npx prisma migrate deploy', {
    env: { ...process.env, DATABASE_URL: url },
    stdio: 'inherit',
  });
};
