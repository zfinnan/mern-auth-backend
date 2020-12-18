// Imports
require('dotenv').config();
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken')
const passport = require('passport');
const JWT_SECRET = process.env.JWT_SECRET;
// Models
const db = require('../models');
// GET api/users/test (Public)
router.get('/test', (req, res) => {
    res.json({ msg: 'User endpoint OK!'});
});
// POST api/users/register (Public)
router.post('/register', (req, res) => {
    console.log('inside of register')
    console.log(req.body);
    console.log(db);
    db.User.findOne({ email: req.body.email })
    .then(user => {
        // if email already exits, send a 400 response
        console.log(user);
        if (user) {
            return res.status(400).json({ msg: 'Email already exists' });
        } else {
            // Create a new user
            console.log('else statement');
            const newUser = new User({
                name: req.body.name,
                email: req.body.email,
                password: req.body.password
            });
            // Salt and hash the password, then save the user
            bcrypt.genSalt(10, (err, salt) => {
                // if (err) throw Error;
                bcrypt.hash(newUser.password, salt, (error, hash) => {
                    // if (error) throw Error;
                    // Change the password in newUser to the hash
                    newUser.password = hash;
                    newUser.save()
                    .then(createdUser => res.json(createdUser))
                    .catch(err => console.log(err));
                })
            })
        }
    })
})

// post api/users/login (public)
router.post('/login', (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
    // find a user via email
    db.User.findOne({ email })
    .then(user => {
        // if there is not a user
        console.log(user)
        if (!user) {
            res.status(400).json({ msg: 'User not found' });
        } else {
            // user is found in the database
            bcrypt.compare(password, user.password)
            .then(isMatch => {
                // check password for a match
                console.log(isMatch)
                if (isMatch) {
                    // user match, send a JSON web token
                    // create a token payload
                    const payload = {
                        id: user.id,
                        email: user.email,
                        name: user.name
                    };

                    // sign token
                    // 3600000 = one hour
                    jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (error, token) =>  {
                        res.json({
                            success: true,
                            token: `Bearer ${token}`
                        });
                    });
                } else {
                    return res.status(400).json({ password: 'Email or Password is incorrect' });
                }
            })
        }
    })
})

module.exports = router;