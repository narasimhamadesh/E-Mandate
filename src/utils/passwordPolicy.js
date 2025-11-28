const Joi = require('joi');

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

module.exports = { validatePassword };
