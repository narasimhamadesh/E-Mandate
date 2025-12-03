const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const config = require('./config');
const logger = require('./utils/logger');
const cookieParser = require('cookie-parser');


const authRoutes = require('./routes/auth.routes');
const npciRoute = require('./routes/npciRoute');
const userRoute = require('./routes/user.routes');
const bankRoute = require('./routes/bank.route');
const mandateRoute = require('./routes/mandate.route');
const userLogsRoutes = require('./routes/userLogs.route');
const mandateCountRoutes = require('./routes/mandateCount.route');
const ocrRoute = require('./routes/ocr.route');
const clientRoute = require('./routes/client.route');
const umrnRoute = require('./routes/umrn.route');


const app = express();
app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

app.use('/api/auth', authRoutes);
app.use('/api/npci', npciRoute);
app.use('/api/users', userRoute);
app.use('/api/banks', bankRoute);
app.use('/api', mandateRoute);
app.use('/api', userLogsRoutes);
app.use('/api', mandateCountRoutes);
app.use("/api/clients", clientRoute);
app.use('/api/ocr', ocrRoute);
app.use('/umrn', umrnRoute);



app.get('/health', (req, res) => res.json({ status: 'ok' }));

module.exports = app;
