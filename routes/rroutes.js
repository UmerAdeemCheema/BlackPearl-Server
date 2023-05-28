const express = require("express");
const actions = require('../methods/actions')
const vulnactions = require('../methods/vulnScanActions')
const router = express.Router();
var middleware = require('../methods/middleware')

// router.get('/', (req,res)=>{
//     res.send('Hello World')
// })

//adding a user
//route POST /adduser
router.post('/adduser', actions.addNewUser)
//authenticate a user
//route POST /authenticate
router.post('/authenticate', actions.authenticate)
router.get('/getInfo', middleware.authenticateToken, actions.getUserInfo)
router.post('/updateAttribute', middleware.authenticateToken, actions.updateattribute)
router.post('/deleteDomainScan', middleware.authenticateToken, vulnactions.deleteDomainScan)

router.get('/getScanHistory', middleware.authenticateToken, actions.getScanHistory)
router.post('/getDomainScanInfo', middleware.authenticateToken, actions.getDomainScanInfo)
router.post('/getDomainScanSubdomains', middleware.authenticateToken, actions.getDomainScanSubdomains)
router.post('/getDomainScanVulnerabilities', middleware.authenticateToken, actions.getDomainScanVulnerabilities)
router.post('/getSubDomainScanVulnerabilities', middleware.authenticateToken, actions.getSubDomainScanVulnerabilities)
router.post('/getSubDomainScanInfo', middleware.authenticateToken, actions.getSubDomainScanInfo)
router.post('/getSubDomainScanPorts', middleware.authenticateToken, actions.getSubDomainScanPorts)
router.post('/getSubDomainScanURLs', middleware.authenticateToken, actions.getSubDomainScanURLs)






router.post('/vulnscan/createVulnerabilityScan', middleware.authenticateAPIKey, vulnactions.createVulnerabilityScan)
router.post('/vulnscan/subdomainsEnumerated', middleware.authenticateAPIKey, vulnactions.subdomainsEnumerated)
router.post('/vulnscan/subdomainScanInitiated', middleware.authenticateAPIKey, vulnactions.subdomainScanInitiated)
router.post('/vulnscan/portScan', middleware.authenticateAPIKey, vulnactions.portScan)
router.post('/vulnscan/dirBrute', middleware.authenticateAPIKey, vulnactions.dirBrute)
router.post('/vulnscan/addVulnerability', middleware.authenticateAPIKey, vulnactions.addVulnerability)
router.post('/vulnscan/switchVulnerability', middleware.authenticateAPIKey, vulnactions.switchVulnerability)
router.post('/vulnscan/completeSubdomainScan', middleware.authenticateAPIKey, vulnactions.completeSubdomainScan)
router.post('/vulnscan/completeDomainScan', middleware.authenticateAPIKey, vulnactions.completeDomainScan)


module.exports = router;