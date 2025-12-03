const db = require("../db");

// Save client data
exports.addClient = async (req, res) => {
    const { companyName, contactPerson, email, phone, address, address2, address3, gstNumber } = req.body;
    
    const sql = "INSERT INTO clients (company_name, contact_person, email, phone, address, address2, address3, gst_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    
    db.query(sql, [companyName, contactPerson, email, phone, address, address2, address3, gstNumber], (err, result) => {
        if (err) {
            console.error("Error inserting data:", err);
            return res.status(500).json({ error: "Database insertion failed" });
        }
        res.status(201).json({ message: "Client added successfully" });
    });
};

// Get all clients
exports.getClients = async(req, res) => {
    const sql = "SELECT * FROM clients";
    
    db.query(sql, (err, results) => {
        if (err) {
            console.error("Error fetching data:", err);
            return res.status(500).json({ error: "Database retrieval failed" });
        }
        res.status(200).json(results);
    });
};

