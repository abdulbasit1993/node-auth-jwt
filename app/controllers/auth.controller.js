const config = require("../config/auth.config");
const db = require("../models");
const User = db.user;
const Role = db.role;

var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");

exports.signup = (req, res) => {
    const user = new User({
        username: req.body.username,
        email: req.body.email,
        password: bcrypt.hashSync(req.body.password, 8)
    });

    user.save((err, user) => {
        if (err) {
            res.status(500).send({ success: false, message: err });
            return;
        }

        if (req.body.roles) {
            Role.find(
                {
                    name: { $in: req.body.roles }
                },
                (err, roles) => {
                    if (err) {
                        res.status(500).send({ success: false, message: err });
                        return;
                    }

                    user.roles = roles.map(role => role._id);
                    user.save(err => {
                        if (err) {
                            res.status(500).send({ success: false, message: err });
                            return;
                        }

                        res.send({ success: true, message: "User was registered successfully!", data: [{ username: user.username, email: user.email, _id: user._id }] });
                    });
                }
            );
        } else {
            Role.findOne({ name: "user" }, (err, role) => {
                if (err) {
                    res.status(500).send({ success: false, message: err });
                    return;
                }

                user.roles = [role._id];
                user.save(err => {
                    if (err) {
                        res.status(500).send({ success: false, message: err });
                        return;
                    }

                    res.send({ success: true, message: "User was registered successfully!", data: [{ username: user.username, email: user.email, _id: user._id }] });
                });
            });
        }
    });
};

exports.signin = (req, res) => {
    User.findOne({
        email: req.body.email
    })
    .populate("roles", "-__v")
    .exec((err, user) => {
        if (err) {
            res.status(500).send({ success: false, message: err });
            return;
        }

        if (!user) {
            return res.status(404).send({ success: false, message: "User Not Found"});
        }

        var passwordIsValid = bcrypt.compareSync(
            req.body.password,
            user.password
        );

        if (!passwordIsValid) {
            return res.status(401).send({
                success: false,
                token: null,
                message: "Invalid Password!"
            });
        }

        var token = jwt.sign({id: user.id }, config.secret, {
            expiresIn: 86400 // 24 hours
        });

        var authorities = [];

        for (let i = 0; i < user.roles.length; i++) {
            authorities.push(user.roles[i].name);
        }
        res.status(200).send({
            success: true,
            data: [{token: token, role: user.roles}],
        });
    });
};
