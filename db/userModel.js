const mongoose = require('mongoose')


const UserSchema = new mongoose.Schema({

    email: {
        type: String,
        required: [true, "Please provide a email"],
        unique: [true, "Email Exist"]
    },

    password: {
        type: String,
        required: [true, "Please provide a password"],
        unique: false,
    },
}, {timestamps: true})

module.exports = mongoose.model.Users || mongoose.model("Users",UserSchema);