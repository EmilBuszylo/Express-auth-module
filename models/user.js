const mongoose = require('mongoose');
const { Schema } = mongoose;

const userSchema = new Schema({

    _id: mongoose.Schema.Types.ObjectId,
    email: { type: String, unique: true, minlength: 3, index: true },
    password: String,
    profile: {
        name: { type: String, default: '' },
        picture: { type: String, default: '' },
        role: { type: String, default: 'default' }
    },
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
