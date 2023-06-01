
const jwt = require('jsonwebtoken');
const secretKey = require('../config/dbconfig').secret
var User = require('../models/user')

var middleware = {
    authenticateToken : function (req, res, next) {
        const token = req.headers['authorization'];
    
        if (!token) {
        return res.status(401).json({ message: 'No token provided' });
        }
    
        jwt.verify(token, secretKey, (err, user) => {
            if (err) {
                return res.status(403).json({ message: 'Invalid token' });
            }
        
            req.user = user;
            next();
        });
    },
    authenticateAPIKey : async function (req, res, next) {
        const email = req.headers['bpemail'];
        const apiKey = req.headers['bpapikey'];
    
        if (!email || !apiKey) {
            return res.status(401).json({ message: 'API Key or Email not provided' });
        }
    
        var user = await User.findOne({email: email})
        if(!user) {
            res.status(403).send({success: false, msg: "Authentication Failed"})
        }
        if(user.apiKey == apiKey){
            req.user = user;
            next();
        }
        else{
            res.status(403).send({success: false, msg: "Authentication Failed"})
        }
    }
}


  module.exports = middleware