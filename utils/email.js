const nodemailer = require("nodemailer");


exports.sendMail = async (options) => {
    //1-create the transporter
    const transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        auth: {
            user: process.env.EMAIL_USERNAME,
            pass: process.env.EMAIL_PASSWORD,
        },
    });

    //2-Define the mail options
    const mailOptions = {
        from: "Elie Bou Abdallah <bouabdallahelie@gamil.com>",
        to: options.email,
        subject: options.subject,
        text: options.message
    }

    //3- Send the email
    await transporter.sendMail(mailOptions);
};