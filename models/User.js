const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        min: 6,
        max: 25
    },
    email:{
        type: String,
        required: true,
        min: 6,
        max: 25
    },
    password:{
        type: String,
        required: true,
        min: 6,
        max: 1024
    },
    isAdmin: Boolean,
    createdAt:{
        type: Date,
        default: Date.now
    }
})

module.exports = mongoose.model('User',userSchema)