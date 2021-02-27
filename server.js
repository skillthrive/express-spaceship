const mongoose = require('mongoose');
const dotenv = require('dotenv');

process.on('uncaughtException', (err) => {
  console.log('UNCAUGHT EXCEPTION! 💥 Shutting down...');
  console.log(err.name, err.message);
  process.exit(1);
});

dotenv.config({ path: './config.env' });

const app = require('./app');

// MongoDB setup
const DB =
  process.env.NODE_ENV == 'production'
    ? process.env.DATABASE.replace('<PASSWORD>', process.env.DATABASE_PASSWORD)
    : process.env.DATABASE_DEV.replace(
        '<PASSWORD>',
        process.env.DATABASE_PASSWORD
      );

mongoose
  .connect(DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log('DB Connection Successful');
  });

const port = process.env.PORT || 4020;

const server = app.listen(port, () => {
  console.log(`App running on port ${port} ...`);
});

// Errors
process.on('unhandledRejection', (err) => {
  console.log('UNHANDLED REJECTION! 💥 Shutting down...');
  console.log(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});

process.on('SIGTERM', () => {
  console.log('SIGTERM RECIEVED 💥 Shutting down gracefully...');
  server.close(() => {
    console.log(`💥 process terminated...`);
  });
});
