var jwtStrategy = require('passport-jwt').Strategy
var ExtractJwt = require('passport-jwt').ExtractJwt

var User = require('../models/userauth')
var config = require('./dbconfig')

module.exports = function (passport) {
    var opt = {}
    opt.secretOrKey = config.secret
    opt.jwtFromRequest = ExtractJwt.fromAuthHeaderWithScheme('jwt')

    passport.use(new jwtStrategy(opt, function(jwt_payload, done){
        User.find({
            id: jwt_payload.id
        }, function (err, user) {
            if(err){
                return done(err, false)
            }
            if(user){
                return done(null, user)
            }
            else {
                return done(null, false)
            }
        }
        )
    }))
}
