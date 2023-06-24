var mongoose = require('mongoose')
var Schema = mongoose.Schema

var subdomainScanSchema= new Schema({
    subdomainName:{
        type: String,
        required:true
    },
    // foreigndomainId:{
    //     type: String,
    //     required:true
    // },
	domainName:{
        type: String,
        required:true
    },
    progress:{
        type: Number,
        required:true
    },
    status:{
        type: String,
        required:true
    },
    email:{
        type: String,
        required:true
    },
	ports:{
        type: mongoose.Schema.Types.Mixed,
        required:true
    },
	urls:{
        type: mongoose.Schema.Types.Mixed,
        required:true
    },
	vulnerabilitiesCount:{
        type: mongoose.Schema.Types.Mixed,
        required:true
    }
})

module.exports = mongoose.model('SubDomainScan', subdomainScanSchema)