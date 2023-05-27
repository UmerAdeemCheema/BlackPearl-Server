var mongoose = require('mongoose')
var Schema = mongoose.Schema

var domainScanSchema= new Schema({
    email:{
        type: String,
        required:true
    },
	domainName:{
        type: String,
        required:true
    },
	startedOn:{
        type: String,
        required:true
    },
	status:{
        type: String,
        required:true
    },
    progress:{
        type: Number,
        required:true
    },
	subdomainsFound:{
        type: mongoose.Schema.Types.Mixed,
        required:true
    },
	vulnerabilities:{
        type: Array,
        required:true
    },
	vulnerabilitiesCount:{
        type: mongoose.Schema.Types.Mixed,
        required:true
    }
})

module.exports = mongoose.model('DomainScan', domainScanSchema)