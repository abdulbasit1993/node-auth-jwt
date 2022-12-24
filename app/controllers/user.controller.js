const db = require("../models");
const User = db.user;
const Role = db.role;
const jwt = require("jsonwebtoken");

exports.allAccess = (req, res) => {
    res.status(200).send("Public Content");
}

exports.userBoard = (req, res) => {
    const token = req.headers.authorization.split(' ')[1];
    const decodedToken = jwt.decode(token);
    const userId = decodedToken.id;

    User.findById(userId)
    .populate("roles", "name")
    .exec((err, data) => {
        if (err) {
            res.status(404).send({ success: false, message: "User Not Found" })
        }
        else {
            res.status(200).send({
                success: true, 
                data: [{ 
                    _id: data._id, 
                    username: data.username,
                    email: data.email,
                    role: [data.roles[0].name]
                 }] })
        }
    });
}

exports.adminBoard = (req, res) => {
    res.status(200).send("Admin Content");
}

exports.moderatorBoard = (req, res) => {
    res.status(200).send("Moderator Content");
}