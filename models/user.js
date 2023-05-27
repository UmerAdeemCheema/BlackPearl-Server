var mongoose = require('mongoose')
var Schema = mongoose.Schema;
var bcrypt = require('bcrypt')

var userSchema= new Schema({
    email: {
        type: String,
        required:true
    },
    name: {
        type: String,
        required:true
    },
    phone: {
        type: String,
        required:true
    },
    password: {
        type: String,
        required:true
    },
    country: {
        type: String,
        required:true
    },
    profilepicname: {
        type: String,
        default:"",
    },
    apiKey: {
        type: String,
        required:true
    },
    vulnScans: {
        type: Array,
        default:[]
    }
})

userSchema.pre('save', function(next){
    var userauth = this;
    if(this.isModified('password') || this.isNew){
        bcrypt.genSalt(10, function(err, salt){
            if(err){
                return next(err)
            }
            bcrypt.hash(userauth.password, salt, function (err, hash){
                if(err){
                    return next(err)
                }
                userauth.password=hash;
                next()
            })
        })
    }
    else{
        return next()
    }
})

userSchema.methods.comparePassword = function (pass, cb) {
    bcrypt.compare(pass, this.password, function(err, isMatch){
        if(err){
            return next(err)
        }
        cb(null, isMatch)
    })
}

module.exports = mongoose.model('User', userSchema)