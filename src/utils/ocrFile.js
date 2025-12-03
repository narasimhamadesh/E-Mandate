const Tesseract = require("tesseract.js");
const fs = require("fs");
 
// Function to extract text from an image file using Tesseract.js
exports.extractTextFromImage = async (filePath) => {
  try {
    const { data: { text } } = await Tesseract.recognize(filePath, "eng", {
      logger: m => console.log(m),
    });
    return text;
  } catch (error) {
    console.error("Tesseract OCR error:", error);
    throw new Error("OCR extraction failed.");
  }
};