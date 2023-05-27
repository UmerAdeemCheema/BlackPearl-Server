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



router.post('/vulnscan/createVulnerabilityScan', middleware.authenticateAPIKey, vulnactions.createVulnerabilityScan)


module.exports = router;