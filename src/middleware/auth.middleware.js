const jwt = require('jsonwebtoken');
const config = require('../config');

const db = require("../db")



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



// ------------------ AUTHENTICATED USER ------------------
function authenticatedUser(req, res, next) {
  const authHeader = req.headers.authorization;

  console.log("Auth Header:", authHeader)

  if (!authHeader) {
    return res.status(401).json({ message: "Authorization header missing" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Token missing" });
  }

  console.log("Token:", token);

  try {
    const payload = jwt.verify(token, config.jwt.accessSecret);

    req.user = {
      id: payload.sub,
      role: payload.role,
      sessionId: payload.sid
    };
    console.log("Authenticated User Payload:", req.user);
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

// ------------------ ROLE AUTHORIZATION ------------------


function authorisedRole(requiredRole) {
  return async (req, res, next) => {
    try {
      let userRoleId = req.user?.role;

      console.log("Authorising Role ID:", userRoleId, "for required role:", requiredRole);

      if (!userRoleId) {
        return res.status(401).json({ message: "Unauthorized: No role found" });
      }

      // Convert string → integer
      userRoleId = parseInt(userRoleId, 10);
      console.log("Converted Role ID:", userRoleId);

      // Query the database for the user's role
      const [roles] = await db.query(
        "SELECT role_name FROM roles WHERE id = ?",
        [userRoleId]
      );

      if (roles.length === 0) {
        return res.status(400).json({ message: "Invalid role ID" });
      }

      const roleName = roles[0].role_name;
      console.log("DB Returned Role:", roleName);

      // Validate required role
      if (roleName.toLowerCase() !== requiredRole.toLowerCase()) {
        return res.status(403).json({ message: "Forbidden: Insufficient permissions" });
      }

      // Success → proceed
      next();

    } catch (error) {
      console.error("Role authorization error:", error);
      return res.status(500).json({ message: "Internal server error" });
    }
  };
}



// ------------------ EXPORT BOTH ------------------
module.exports = {
  authenticatedUser,
  authorisedRole
};
