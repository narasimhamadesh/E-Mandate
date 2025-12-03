function generateUMRN() {
    const timestamp = Date.now().toString();
    const random = Math.random().toString(36).substring(2, 8).toUpperCase();
    return `UMRN${timestamp.slice(-8)}${random}`;
  }
module.exports = generateUMRN;  