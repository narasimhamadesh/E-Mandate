const jwt = require('jsonwebtoken');
const config = require('../config');



// module.exports = function authMiddleware(req, res, next) {
//   const auth = req.headers.authorization;
//   if (!auth) return res.status(401).json({ message: 'No token' });
//   const token = auth.split(' ')[1];
//   try {
//     const payload = jwt.verify(token, config.jwt.accessSecret);
//     req.user = { id: payload.sub, role: payload.role, sessionId: payload.sid };
//     return next();
//   } catch (err) {
//     return res.status(401).json({ message: 'Invalid token' });
//   }
// };


module.exports = function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  console.log("Authorization Header:", authHeader);

  if (!authHeader) {
    return res.status(401).json({ message: "Authorization header missing" });
  }

  const token = authHeader.split(" ")[1]; // Bearer <token>
  if (!token) {
    return res.status(401).json({ message: "Token missing" });
  }

  try {
    const payload = jwt.verify(token, config.jwt.accessSecret);

    // Attach authenticated user to request
    req.user = {
      id: payload.sub,
      role: payload.role,
      sessionId: payload.sid
    };

    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};
