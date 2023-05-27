
var DomainScan = require('../models/domainscan')



var vulnfunctions = {
    createVulnerabilityScan: async function (req, res) {
        if (!req.body.domainname) {
          res.json({ success: false, msg: 'Enter all Fields' });
        } 
        else {
            const scan = await DomainScan.findOne({ email: req.body.email });
      
            if (scan) {
              res.status(403).send({ success: false, msg: 'Domain already scanned, delete older scans to continue' });
            } 
            else {
                const newDomainScan = new DomainScan({
                    email: req.user.email,
                    domainName: req.body.domainname,
                    startedOn: getDate(),
                    status:"Running",
                    progress:0,
                    subdomainsFound:{"numberOfSubdomains": 0, "numberOfActiveSubdomains": 0, "array":[]},
                    vulnerabilities:[],
                    vulnerabilitiesCount:{"Critical":0,"High":0,"Medium":0,"Low":0}
                });
                console.log(newDomainScan)
              
                var savedScan = await newDomainScan.save()
                res.json({ success: true, msg: 'Successfully saved', scan: savedScan });
               
            }
          
        }
    }
}


function getDate() {
    const currentDate = new Date();
    const day = String(currentDate.getDate()).padStart(2, '0');
    const month = String(currentDate.getMonth() + 1).padStart(2, '0'); // Note: month is zero-based
    const year = currentDate.getFullYear();

    const formattedDate = `${day}/${month}/${year}`;
    return formattedDate;
}


module.exports = vulnfunctions