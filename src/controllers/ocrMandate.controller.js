require("dotenv").config();
const fs = require("fs");
const axios = require("axios");

const API_KEY = process.env.GOOGLE_VISION_API_KEY;
const API_URL = `https://vision.googleapis.com/v1/images:annotate?key=${API_KEY}`;

exports.extractTextFromImage = async (req, res) => {
  try {
    if (!API_KEY) {
      return res.status(500).json({ error: "Google Vision API key missing in .env" });
    }

    if (!req.file) {
      return res.status(400).json({ error: "No image uploaded" });
    }

    const imageBuffer = fs.readFileSync(req.file.path);
    const base64Image = imageBuffer.toString("base64");

    const requestBody = {
      requests: [
        {
          image: { content: base64Image },
          features: [{ type: "DOCUMENT_TEXT_DETECTION" }],
        },
      ],
    };

    const response = await axios.post(API_URL, requestBody, {
      headers: { "Content-Type": "application/json" },
    });

    const annotations = response.data.responses[0]?.fullTextAnnotation;

    res.json({ text: annotations?.text || "No text found" });

    // Cleanup temporary file
    fs.unlinkSync(req.file.path);

  } catch (error) {
    console.error("OCR Error:", error.message);

    if (req.file) {
      fs.unlinkSync(req.file.path); // Delete file even on error
    }

    res.status(500).json({ error: "Error processing image" });
  }
};
