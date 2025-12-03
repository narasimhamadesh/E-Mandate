const Joi = require('joi');
const crypto = require("crypto");

const passwordSchema = Joi.string()
  .min(10)
  .max(128)
  .regex(/[a-z]/, 'lowercase')
  .regex(/[A-Z]/, 'uppercase')
  .regex(/[0-9]/, 'number')
  .regex(/[^a-zA-Z0-9]/, 'special')
  .message('Password must have upper, lower, number and symbol and min length 10.');

function validatePassword(password) {
  const { error } = passwordSchema.validate(password);
  return error ? error.message : null;
}






// Generate a strong random password
function generatePassword(length = 12){
  const chars =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+=-`~[]{}|;\':",./<>?';

  let pwd = "";
  for (let i = 0; i < length; i++) {
    pwd += chars.charAt(crypto.randomInt(0, chars.length));
  }
  return pwd;
};




module.exports = { validatePassword , generatePassword };
