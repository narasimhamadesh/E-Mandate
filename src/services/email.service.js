// const nodemailer = require("nodemailer");

// const sendMandateEmail = async (toEmail, fullName, mandateId) => {
//   try {
//     const transporter = nodemailer.createTransport({
//       service: "gmail",
//       auth: {
//         // user: "harshithan.dev@gmail.com", // replace with your email
//         // pass: "sbqn cdao tjhj bair",    // use an app password
//         user: process.env.EMAIL_USER, 
//         pass: process.env.EMAIL_PASS 
//       },
//     });

//     const authLink = `${process.env.FRONTEND_URL}/authorize-mandate/${mandateId}`;

//     const mailOptions = {
//       from: '"E-Mandate Service" <nmitsolutions@gmail.com>',
//       to: toEmail,
//       subject: "Action Required: Authorize Your E-Mandate",
//       html: `
//         <div style="font-family: Arial, sans-serif; color: #333;">
//           <h2>Hello ${fullName},</h2>
//           <p>We have received your E-Mandate submission. To complete the process, please authorize it using the link below:</p>
//           <p>
//             <a href="${authLink}" style="background-color: #007bff; color: #fff; padding: 10px 15px; text-decoration: none; border-radius: 5px;">
//               Authorize Mandate
//             </a>
//           </p>
//           <p>If the button above doesn’t work, copy and paste the following link in your browser:</p>
//           <p>${authLink}</p>
//           <p>Thank you,<br/>E-Mandate Team</p>
//         </div>
//       `,
//     };

//     const info = await transporter.sendMail(mailOptions);
//     console.log("Email sent:", info.response);
//     console.log("Sending email to:", email);
//   } catch (error) {
//     console.error("Error sending email:", error.message);
//   }
// };



// /**
//  * Send an email
//  * @param {string} to - recipient email
//  * @param {string} subject - subject line
//  * @param {string} text - plain text body
//  * @param {string|null} html - HTML email body (optional)
//  */
// const sendEmail = async ({ to, subject, text = null }) => {
//   try {
//     const mailOptions = {
//       from: process.env.EMAIL_USER,
//       to,
//       subject,
//       text
//     };

//     await transporter.sendMail(mailOptions);

//     console.log("📧 Email sent successfully to:", to);
//     return true;
//   } catch (err) {
//     console.error("Email sending error:", err);
//     throw new Error("Email sending failed");
//   }
// };






// module.exports = { sendMandateEmail ,sendEmail};









const nodemailer = require("nodemailer");

// ===========================
// GLOBAL EMAIL TRANSPORTER
// ===========================
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ===========================
// SEND MANDATE EMAIL
// ===========================
const sendMandateEmail = async (toEmail, fullName, mandateId) => {
  try {
    const authLink = `${process.env.FRONTEND_URL}/authorize-mandate/${mandateId}`;

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: toEmail,
      subject: "Action Required: Authorize Your E-Mandate",
      html: `
        <div>
          <h2>Hello ${fullName},</h2>
          <p>Please authorize your mandate:</p>
          <p><a href="${authLink}">${authLink}</a></p>
        </div>
      `,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log("Email sent:", info.response);
  } catch (error) {
    console.error("Error sending mandate email:", error.message);
  }
};

// ===========================
// GENERIC EMAIL SENDER
// ===========================
const sendEmail = async ({ to, subject, text = null, html = null }) => {
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to,
      subject,
      text,
      html,
    };

    await transporter.sendMail(mailOptions);

    console.log("📧 Email sent successfully to:", to);
    return true;
  } catch (err) {
    console.error("Email sending error:", err);
    throw new Error("Email sending failed");
  }
};

module.exports = { sendMandateEmail, sendEmail };

