const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const authRoutes = require('./routes/auth.routes');
const npciRoute = require('./routes/npciRoute');
const userRoute = require('./routes/user.routes');
const bankRoute = require('./routes/bank.route');
const config = require('./config');
const logger = require('./utils/logger');

const app = express();
app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

app.use('/api/auth', authRoutes);
app.use('/api/npci', npciRoute);
app.use('/api/users', userRoute);
app.use('/api/banks', bankRoute);

app.get('/health', (req, res) => res.json({ status: 'ok' }));

module.exports = app;
