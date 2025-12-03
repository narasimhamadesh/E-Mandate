const express = require('express');
const router = express.Router();
const {authenticatedUser,authorisedRole}= require('../middleware/auth.middleware');

const {getUsers,createUser,updatePassword} = require('../controllers/user.controller');



router.get('/', authenticatedUser,getUsers); 
router.post('/create-user', authenticatedUser,authorisedRole('admin'), createUser); 
router.post('/update-password', authenticatedUser, updatePassword);


module.exports = router;