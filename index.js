const app = require('./src/app');
const config = require('./src/config');
const {logger} = require('./src/utils/logger');

const port = config.port || 3001;
app.listen(port, () => {
  logger.info(`Server started on port ${port}`);
});
