const express = require('express');
const router = express.Router();
const {authenticatedUser,authorisedRole}= require('../middleware/auth.middleware');

const {getUsers,updatePassword} = require('../controllers/user.controller');



router.get('/', authenticatedUser,getUsers); 
router.post('/update-password', authenticatedUser, updatePassword);


module.exports = router;