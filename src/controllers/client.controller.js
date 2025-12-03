const db = require("../db");

// Save client data
exports.addClient = async (req, res) => {
    try {
        const { companyName, contactPerson, email, phone, address, address2, address3, gstNumber } = req.body;

        const sql = `
            INSERT INTO clients 
            (company_name, contact_person, email, phone, address, address2, address3, gst_number) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const [result] = await db.query(sql, [
            companyName,
            contactPerson,
            email,
            phone,
            address,
            address2,
            address3,
            gstNumber
        ]);

        return res.status(201).json({
            message: "Client added successfully",
            clientId: result.insertId
        });

    } catch (err) {
        console.error("Error inserting data:", err);
        return res.status(500).json({ error: "Database insertion failed" });
    }
};


// Get all clients
exports.getClients = async (req, res) => {
    try {
        const sql = "SELECT * FROM clients";

        const [results] = await db.query(sql);

        return res.status(200).json(results);

    } catch (err) {
        console.error("Error fetching data:", err);
        return res.status(500).json({ error: "Database retrieval failed" });
    }
};
