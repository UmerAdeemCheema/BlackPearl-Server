
var User = require('../models/user')
var DomainScan = require('../models/domainscan')
var SubDomainScan = require('../models/subdomainscan')
const jwt = require('jsonwebtoken')
const secretKey = require('../config/dbconfig').secret
var bcrypt = require('bcrypt')



var functions = {
    addNewUser: async function (req, res) {
        if (!req.body.name || !req.body.email || !req.body.password || !req.body.phone || !req.body.country) {
          res.json({ success: false, msg: 'Enter all Fields' });
        } else {
          try {
            const user = await User.findOne({ email: req.body.email });
      
            if (user) {
              res.status(403).send({ success: false, msg: 'Email Already exists, Change Email Address' });
            } else {
              const apikey = generateApiKey();
      
              const newUser = new User({
                email: req.body.email,
                name: req.body.name,
                phone: req.body.phone,
                password: req.body.password,
                country: req.body.country,
                profilepicname: 'default',
                apiKey: apikey,
                vulnScans: []
              });
      
              const savedUser = await newUser.save();
      
              res.json({ success: true, msg: 'Account successfullcreated'});
            }
          } catch (err) {
            res.json({ success: false, msg: 'Failed to Save', err: err });
          }
        }
    },
    authenticate: async function(req, res) {
        if((!req.body.email) || (!req.body.password)){
            res.json({success:false, msg: 'Enter all Fields'})
        }
        else{
            var user = await User.findOne({email: req.body.email})
            if(!user) {
                res.status(403).send({success: false, msg: "Authentication Failed, User not Found"})
            }
            else {
                user.comparePassword(req.body.password, function (err, isMatch){
                    if(isMatch && !err){
                        const token = jwt.sign({email : user.email, apiKey: user.apiKey} , secretKey, { expiresIn: '1h' });
                        user = {
                            email: user.email,
                            name: user.name,
                            phone: user.phone,
                            country: user.country,
                            profilepicname: user.profilepicname,
                            apiKey: user.apiKey,
                            vulnScans: user.vulnScans
                        }
                        res.json({success:true, token:token, user: user})
                    }
                    else {
                        res.status(403).send({success: false, msg: "Authentication Failed, Incorrect Password"})
                    }
                })
            }
            
        }
    },
    getUserInfo: async function (req, res) {
        const token = req.headers['authorization'];
        var user = await User.findOne({email: req.user.email})
        if(user) {
            user = {
                email: user.email,
                name: user.name,
                phone: user.phone,
                country: user.country,
                profilepicname: user.profilepicname,
                apiKey: user.apiKey,
                vulnScans: user.vulnScans
            }
            res.json({success:true, token:token, user: user})
        }
        else {
            res.status(403).send({success: false, msg: "User doesn't exists."})
        }
    },

    updateattribute: async function(req, res) {
        if ((!req.body.attribute) || (!req.body.newvalue)){
            return res.status(200).json({success:false, msg: 'Enter all Fields'})
        }
        if(req.body.attribute == 'info')
        {
            if ((!req.body.newvalue.name) || (!req.body.newvalue.phone)){
                return res.status(400).json({success:false, msg: 'Enter all Fields'})
            }
            console.log(req.body.newvalue.name)
            var user = await User.findOneAndUpdate(
                { email: req.user.email },
                { $set: { name : req.body.newvalue.name, phone : req.body.newvalue.phoneno} },
                { new: true }
            )
            if (user){
                return res.status(200).send({success: true, msg: "attribute updated"})
            } 
            else{
                return res.status(404).json({success:false, msg: 'User not found'})
            }
        }
        else if(req.body.attribute == 'password'){
            if ((!req.body.newvalue.oldpassword) || (!req.body.newvalue.newpassword) || (!req.body.newvalue.confirmpassword)){
                return res.status(400).json({success:false, msg: 'Enter all Fields'})
            }
            if(!(req.body.newvalue.newpassword == req.body.newvalue.confirmpassword)){
                return res.status(400).json({success:false, msg: 'New Password and Confirm Password does not match'})
            }
            var user = await User.findOne({email: req.user.email})
            if(!user) {
                res.status(403).send({success: false, msg: "Authentication Failed, User not Found"})
            }
            else {
                user.comparePassword(req.body.newvalue.oldpassword, function (err, isMatch){
                    if(isMatch && !err){
                        bcrypt.genSalt(10, function(err, salt){
                            if(err){
                                return res.status(200).send({success: false, msg: "Error"});
                            }
                            bcrypt.hash(req.body.newvalue.newpassword, salt, async function (err, hash){
                                if(err){
                                    return res.status(200).send({success: false, msg: "Error"});
                                }
                                pass = hash;
                                var index = await User.findOneAndUpdate(
                                    { email: req.user.email },
                                    { $set: { password : pass} })
                                if (index){
                                    return res.status(200).send({success: true, msg: "attribute updated"})
                                } 
                                else{
                                    return res.status(200).json({success:false, msg: 'User not found'})
                                }
                            })
                        })
                    }
                    else {
                        res.status(403).send({success: false, msg: "Authentication Failed, Incorrect Password"})
                    }
                })
            }
        }
        else if(req.body.attribute == 'email'){

            if ((!req.body.newvalue.email) || (!req.body.newvalue.password)){
                return res.status(400).json({success:false, msg: 'Enter all Fields'})
            }
            var user = await User.findOne({email: req.user.email})

            if (!user){
                return res.status(200).send({success: true, msg: "User not found"})
            } 

            user.comparePassword(req.body.newvalue.password, async function (err, isMatch){
                if(isMatch && !err){
                    var auser = await User.findOne({email: req.body.newvalue.email})
                    if(auser) {
                        return res.status(200).send({success: false, msg: "Email Already exists, Change Email Address"})
                    }

                    var index = await User.findOneAndUpdate(
                        { email: req.user.email },
                        { $set: { email : req.body.newvalue.email} })
                    if (index){
                        const token = jwt.sign({email : user.email} , secretKey, { expiresIn: '1h' });
                        return res.status(200).send({success: true, token: token, msg: "attribute updated"}) 
                    } 
                    else{
                        return res.status(200).json({success:false, msg: 'User not found'})
                    }
                        

                }
                else {
                    res.status(403).send({success: false, msg: "Incorrect Password"})
                }
            })
        }
        else{
            return res.status(200).json({success:false, msg: 'Illegal attribute name'})
        }
    },

    getScanHistory: async function(req, res) {
        var history = await User.findOne({email: req.user.email}).select('vulnScans')
        if(!history) {
            res.status(403).send({success: false, msg: "User Not Found"})
        }
        else{
            res.status(200).send({success: true, history: history, msg: "History Found"})
        }
    },

    getDomainScanInfo: async function(req, res) {
        if ((!req.body.domainname)){
            return res.status(400).json({success:false, msg: 'Enter all Fields'})
        }
        var domainscan = await DomainScan.findOne({email: req.user.email, domainName: req.body.domainname}, 'domainName startedOn status progress vulnerabilitiesCount')
        if(!domainscan) {
            res.status(403).send({success: false, msg: "Scan Not Found"})
        }
        else{
            res.status(200).send({success: true, scanInfo: domainscan, msg: "Scan Found"})
        }
    },

    getDomainScanSubdomains: async function(req, res) {
        if ((!req.body.domainname)){
            return res.status(400).json({success:false, msg: 'Enter all Fields'})
        }
        var domainscan = await DomainScan.findOne({email: req.user.email, domainName: req.body.domainname}, 'domainName subdomainsFound')
        if(!domainscan) {
            res.status(403).send({success: false, msg: "Scan Not Found"})
        }
        else{
            res.status(200).send({success: true, scanSubdomains: domainscan, msg: "Scan Subdomains Found"})
        }
    },

    getDomainScanVulnerabilities: async function(req, res) {
        if ((!req.body.domainname)){
            return res.status(400).json({success:false, msg: 'Enter all Fields'})
        }
        var vulnerabilities = await DomainScan.findOne({email: req.user.email, domainName: req.body.domainname}, 'vulnerabilities')
        if(!vulnerabilities) {
            res.status(403).send({success: false, msg: "Scan Not Found"})
        }
        else{
            res.status(200).send({success: true, vulnerabilities: vulnerabilities, msg: "Scan Vulnerabilities Found"})
        }
    },

    getSubDomainScanVulnerabilities: async function(req, res) {
        if ((!req.body.domainname || !req.body.subdomainname)){
            return res.status(400).json({success:false, msg: 'Enter all Fields'})
        }
        var subvulnerabilities = await DomainScan.findOne({email: req.user.email, domainName: req.body.domainname}, { vulnerabilities: { $elemMatch: { subdomainname: "www.vulnweb.com" } }})
        if(!subvulnerabilities) {
            res.status(403).send({success: false, msg: "Scan Not Found"})
        }
        else{
            res.status(200).send({success: true, vulnerabilities: subvulnerabilities, msg: "Scan Vulnerabilities Found"})
        }
    },

    getSubDomainScanInfo: async function(req, res) {
        if ((!req.body.domainname || !req.body.subdomainname)){
            return res.status(400).json({success:false, msg: 'Enter all Fields'})
        }
        var subdomainscan = await SubDomainScan.findOne({email: req.user.email, domainName: req.body.domainname, subdomainName: req.body.subdomainname }, 'subdomainName domainName status progress vulnerabilitiesCount')
        if(!subdomainscan) {
            res.status(403).send({success: false, msg: "Scan Not Found"})
        }
        else{
            res.status(200).send({success: true, scanInfo: subdomainscan, msg: "Scan Found"})
        }
    },

    getSubDomainScanPorts: async function(req, res) {
        if ((!req.body.domainname || !req.body.subdomainname)){
            return res.status(400).json({success:false, msg: 'Enter all Fields'})
        }
        var subdomainscan = await SubDomainScan.findOne({email: req.user.email, domainName: req.body.domainname, subdomainName: req.body.subdomainname }, 'subdomainName domainName ports')
        if(!subdomainscan) {
            res.status(403).send({success: false, msg: "Scan Not Found"})
        }
        else{
            res.status(200).send({success: true, scanInfo: subdomainscan, msg: "Scan Found"})
        }
    },

    getSubDomainScanURLs: async function(req, res) {
        if ((!req.body.domainname || !req.body.subdomainname)){
            return res.status(400).json({success:false, msg: 'Enter all Fields'})
        }
        var subdomainscan = await SubDomainScan.findOne({email: req.user.email, domainName: req.body.domainname, subdomainName: req.body.subdomainname }, 'subdomainName domainName urls')
        if(!subdomainscan) {
            res.status(403).send({success: false, msg: "Scan Not Found"})
        }
        else{
            res.status(200).send({success: true, scanInfo: subdomainscan, msg: "Scan Found"})
        }
    },
}

function generateApiKey() {
    const apiKeyPrefix = "black-bp-";
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const length = 30;
    let apiKey = apiKeyPrefix;
  
    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * characters.length);
      apiKey += characters[randomIndex];
    }
  
    return apiKey;
}

module.exports = functions