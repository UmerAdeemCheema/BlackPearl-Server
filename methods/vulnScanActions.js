
var DomainScan = require('../models/domainscan')
var User = require('../models/user')
var SubDomainScan = require('../models/subdomainscan')



var vulnfunctions = {
    createVulnerabilityScan: async function (req, res) {
        if (!req.body.domainname) {
          res.json({ success: false, msg: 'Enter all Fields' });
        } 
        else {
            const domainExists = req.user.vulnScans.some(scan => scan.domainName === req.body.domainname);
      
            if (domainExists) {
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
              
                var savedScan = await newDomainScan.save()
                
                var vulnUserAppend= {
                    foreignDomainId :savedScan._id,
                    domainName: req.body.domainname,
                    subDomainsScanned: 0,
                    status: "Running",
                    process: "Subdomain Enumeration",
                    inProcessSubdomain:""
                }

                await User.findOneAndUpdate(
                    { email: req.user.email },
                    { $push: { vulnScans: vulnUserAppend } },
                    { new: true }
                )
                res.json({ success: true, msg: 'Successfully saved', scan: savedScan });
               
            }
          
        }
    },

    subdomainsEnumerated: async function (req, res) {
        if (!req.body.domainname || !req.body.data) {
          res.json({ success: false, msg: 'Enter all Fields' });
        } 
        else if(!isSubdomainListValidObject(req.body.data)){
            res.status(403).send({ success: false, msg: 'data object not valid' });
        }
        else {
            const conflict = req.user.vulnScans.some(scan => (scan.domainName === req.body.domainname && scan.process == "Subdomain Enumeration" && scan.status == "Running" && scan.status == "Running"));
            
            if (!conflict) {
              res.status(403).send({ success: false, msg: 'There is a conflict in the Synchronization of data' });
            } 
            else {
                
                await DomainScan.findOneAndUpdate(
                    { email: req.user.email, domainName: req.body.domainname },
                    { $set: { subdomainsFound: req.body.data } },
                    { new: true }
                )

                await User.findOneAndUpdate(
                    { email: req.user.email, 'vulnScans.domainName': req.body.domainname },
                    { $set: { 'vulnScans.$.process': 'Vulnerability 1' } },
                    { new: true }
                )

                res.json({ success: true, msg: 'Successfully saved' });
               
            }
          
        }
    },

    subdomainScanInitiated: async function (req, res) {
        if (!req.body.domainname || !req.body.subdomainname) {
          res.json({ success: false, msg: 'Enter all Fields' });
        } 
        else if (!req.body.subdomainname.endsWith(req.body.domainname)) {
            res.json({ success: false, msg: 'Invalid Subdomain' });
        } 
        else {
            const conflict = req.user.vulnScans.some(scan => (scan.domainName === req.body.domainname && scan.process === "Start Subdomain"  && scan.status == "Running"));
      
            if (!conflict) {
              res.status(403).send({ success: false, msg: 'There is a conflict in the Synchronization of data' });
            } 
            else {

                const subdomainExists = await SubDomainScan.findOne({email: req.user.email, domainName: req.body.domainname, subdomainName: req.body.subdomainname})
      
                if (subdomainExists) {
                    res.status(403).send({ success: false, msg: 'SubDomain scan already created, delete older scans to continue' });
                    return;
                } 
                
                const newSubDomainScan = new SubDomainScan({
                    email: req.user.email,
                    domainName: req.body.domainname,
                    subdomainName: req.body.subdomainname,
                    status:"Running",
                    progress:0,
                    ports:{"numberOfRunningPorts": 0, "array": []},
                    urls:{"numberOfURLs": 0, "array": []},
                    vulnerabilitiesCount:{"Critical":0,"High":0,"Medium":0,"Low":0}
                });
              
                var savedScan = await newSubDomainScan.save()

                await User.findOneAndUpdate(
                    { email: req.user.email, 'vulnScans.domainName': req.body.domainname },
                    { $set: { 'vulnScans.$.inProcessSubdomain': req.body.subdomainname, 'vulnScans.$.process': 'Port Scan' } },
                    { new: true }
                )
                res.json({ success: true, msg: 'Successfully saved', scan: savedScan });
               
            }
          
        }
    },

  portScan: async function (req, res) {
      if (!req.body.domainname || !req.body.subdomainname || !req.body.data) {
        res.json({ success: false, msg: 'Enter all Fields' });
      } 
      else if (typeof req.body.data !== 'object' || !Array.isArray(req.body.data.array) || typeof req.body.data.numberOfRunningPorts !== 'number') {
        res.status(403).send({ success: false, msg: 'data object not valid' });
      }
      else {
          const conflict = req.user.vulnScans.some(scan => (scan.domainName === req.body.domainname && scan.inProcessSubdomain === req.body.subdomainname && scan.process === "Port Scan" && scan.status == "Running"));
          
          if (!conflict) {
            res.status(403).send({ success: false, msg: 'There is a conflict in the Synchronization of data' });
          } 
          else {

              await SubDomainScan.findOneAndUpdate(
                { email: req.user.email, domainName: req.body.domainname, subdomainName: req.body.subdomainname },
                { $set: { ports: req.body.data } },
                { new: true }
              )

              await User.findOneAndUpdate(
                  { email: req.user.email, 'vulnScans.domainName': req.body.domainname },
                  { $set: { 'vulnScans.$.process': 'DirBrute' } },
                  { new: true }
              )
              res.json({ success: true, msg: 'Successfully saved'});
             
          }
      }
  },

  dirBrute: async function (req, res) {
    if (!req.body.domainname || !req.body.subdomainname || !req.body.data) {
      res.json({ success: false, msg: 'Enter all Fields' });
    } 
    else if (typeof req.body.data !== 'object' || !Array.isArray(req.body.data.array) || typeof req.body.data.numberOfURLs !== 'number') {
      res.status(403).send({ success: false, msg: 'data object not valid' });
    }
    else {
        const conflict = req.user.vulnScans.some(scan => (scan.domainName === req.body.domainname && scan.inProcessSubdomain === req.body.subdomainname && scan.process === "DirBrute" && scan.status == "Running"));
        
        if (!conflict) {
          res.status(403).send({ success: false, msg: 'There is a conflict in the Synchronization of data' });
        } 
        else {
            await SubDomainScan.findOneAndUpdate(
              { email: req.user.email, domainName: req.body.domainname, subdomainName: req.body.subdomainname },
              { $set: { urls: req.body.data } },
              { new: true }
            )
            await User.findOneAndUpdate(
                { email: req.user.email, 'vulnScans.domainName': req.body.domainname },
                { $set: { 'vulnScans.$.process': 'Vulnerability 3' } },
                { new: true }
            )
            res.json({ success: true, msg: 'Successfully saved'});
          
        }
    }
  },

  addVulnerability: async function (req, res) {
    if (!req.body.domainname || !req.body.subdomainname || !req.body.data || !req.body.data.vulnerability_id || !req.body.data.severity) {
      res.json({ success: false, msg: 'Enter all Fields' });
    }
    else {
        const conflict = req.user.vulnScans.some(scan => (scan.domainName === req.body.domainname && scan.inProcessSubdomain === req.body.subdomainname && scan.process.startsWith("Vulnerability") && scan.status == "Running" && parseInt(scan.process.split(' ')[1]) == req.body.data.vulnerability_id ));
        if (!conflict) {
          res.status(403).send({ success: false, msg: 'There is a conflict in the Synchronization of data' });
        } 
        else {
          if (!(req.body.data.severity === "Low" || req.body.data.severity === "Medium" || req.body.data.severity === "High" || req.body.data.severity === "Critical")) {
            res.status(403).send({ success: false, msg: 'Invalid Severity' });
            return;
          }
          var vulncategory = 'vulnerabilitiesCount.'+req.body.data.severity

          await DomainScan.findOneAndUpdate(
            { email: req.user.email, domainName: req.body.domainname },
            { $push: { vulnerabilities: req.body.data }, $inc: { [vulncategory]: 1 } },
            { new: true }
          )

          if(req.body.data.vulnerability_id == 1 || req.body.data.vulnerability_id == 2){
            res.json({ success: true, msg: 'Successfully saved'});
          }

          await SubDomainScan.findOneAndUpdate(
            { email: req.user.email, domainName: req.body.domainname, subdomainName: req.body.subdomainname },
            { $inc: { [vulncategory]: 1 } },
            { new: true }
          )

          res.json({ success: true, msg: 'Successfully saved'});
          
        }
    }
  },

  switchVulnerability: async function (req, res) {
    if (!req.body.domainname || !req.body.vulnerability_id) {
      res.json({ success: false, msg: 'Enter all Fields' });
    } 
    else if (typeof req.body.vulnerability_id !== 'number') {
      res.json({ success: false, msg: 'Invalid Vulnerability Id' });
    }
    else {
        const conflict = req.user.vulnScans.some(scan => (scan.domainName === req.body.domainname && scan.process === "Vulnerability "+req.body.vulnerability_id && scan.status == "Running"));
        
        if (!conflict) {
          res.status(403).send({ success: false, msg: 'There is a conflict in the Synchronization of data' });
        } 
        else {
          var vuln = "Vulnerability "+(req.body.vulnerability_id+1)
            // await SubDomainScan.findOneAndUpdate(
            //   { email: req.user.email, domainName: req.body.domainname, subdomainName: req.body.subdomainname },
            //   { $set: { urls: req.body.data } },
            //   { new: true }
            // )
            if(req.body.vulnerability_id == 2){
              vuln = "Start Subdomain"
            }
            await User.findOneAndUpdate(
                { email: req.user.email, 'vulnScans.domainName': req.body.domainname },
                { $set: { 'vulnScans.$.process': vuln } },
                { new: true }
            )
            res.json({ success: true, msg: 'Successfully saved'});
          
        }
    }
  },

  completeSubdomainScan: async function (req, res) {
    if (!req.body.domainname || !req.body.subdomainname) {
      res.json({ success: false, msg: 'Enter all Fields' });
    } 
    else {
        const conflict = req.user.vulnScans.some(scan => (scan.domainName === req.body.domainname && scan.inProcessSubdomain === req.body.subdomainname && scan.process.startsWith("Vulnerability") && scan.status == "Running"));
  
        if (!conflict) {
          res.status(403).send({ success: false, msg: 'There is a conflict in the Synchronization of data' });
        } 
        else {

          await SubDomainScan.findOneAndUpdate(
            { email: req.user.email, domainName: req.body.domainname, subdomainName: req.body.subdomainname },
            { $set: { progress: 100, status:"Start Subdomain", } },
            { new: true }
          )

            await User.findOneAndUpdate(
                { email: req.user.email, 'vulnScans.domainName': req.body.domainname },
                { $set: { 'vulnScans.$.inProcessSubdomain': "", 'vulnScans.$.process': 'Start Subdomain' }, $inc: { 'vulnScans.$.subDomainsScanned': 1 } },
                { new: true }
            )
            res.json({ success: true, msg: 'Successfully saved' });
           
        }

    }
  },

  completeDomainScan: async function (req, res) {
    if (!req.body.domainname) {
      res.json({ success: false, msg: 'Enter all Fields' });
    } 
    else {
        const conflict = req.user.vulnScans.some(scan => (scan.domainName === req.body.domainname) && scan.status == "Running");
  
        if (!conflict) {
          res.status(403).send({ success: false, msg: 'There is a conflict in the Synchronization of data' });
        } 
        else {
          var noOfsubDomains = await DomainScan.findOne({ email: req.user.email, domainName: req.body.domainname }).select('subdomainsFound.numberOfActiveSubdomains')
          noOfsubDomains = noOfsubDomains.subdomainsFound.numberOfActiveSubdomains

          const conflict2 = req.user.vulnScans.some(scan => (scan.domainName === req.body.domainname && scan.subDomainsScanned === noOfsubDomains));

          if (!conflict2) {
            res.status(403).send({ success: false, msg: 'There is a conflict in the Synchronization of data' });
          } 
          else {
            await DomainScan.findOneAndUpdate(
              { email: req.user.email, domainName: req.body.domainname },
              { $set: { progress: 100, status:"Completed", } },
              { new: true }
            )

              await User.findOneAndUpdate(
                  { email: req.user.email, 'vulnScans.domainName': req.body.domainname },
                  { $set: { 'vulnScans.$.process': 'Completed' } },
                  { new: true }
              )
              res.json({ success: true, msg: 'Successfully saved' });
          }
           
        }

    }
  },

  deleteDomainScan: async function (req, res) {
    if (!req.body.domainname) {
      res.status(403).send({ success: false, msg: 'Enter all Fields' });
    } 
    else {
        
      await DomainScan.findOneAndDelete({ email: req.user.email, domainName: req.body.domainname })
      await SubDomainScan.deleteMany({ email: req.user.email, domainName: req.body.domainname })

      await User.updateOne(
        { email: req.user.email }, 
        { $pull: { vulnScans: { domainName: req.body.domainname } } } 
      )
      res.json({ success: true, msg: 'Successfully saved' });
    }
  },

  updateScanStatus: async function (req, res) {
    if (!req.body.domainname || !req.body.status) {
      res.status(403).send({ success: false, msg: 'Enter all Fields' });
    } 
    else {
      const conflict = req.user.vulnScans.some(scan => (scan.domainName === req.body.domainname));

      if (!conflict) {
        res.status(403).send({ success: false, msg: 'There is a conflict in the Synchronization of data' });
      } 
      else {
          await DomainScan.findOneAndUpdate(
            { email: req.user.email, domainName: req.body.domainname },
            { $set: { status:req.body.status, } },
            { new: true }
          )
            await User.findOneAndUpdate(
                { email: req.user.email, 'vulnScans.domainName': req.body.domainname },
                { $set: { 'vulnScans.$.status': req.body.status } },
                { new: true }
            )
            res.json({ success: true, msg: 'Successfully saved' });
      }
    }
  },

}


function getDate() {
    const currentDate = new Date();
    const day = String(currentDate.getDate()).padStart(2, '0');
    const month = String(currentDate.getMonth() + 1).padStart(2, '0'); // Note: month is zero-based
    const year = currentDate.getFullYear();

    const formattedDate = `${day}/${month}/${year}`;
    return formattedDate;
}

function isSubdomainListValidObject(obj) {
    // Check if the object has the required properties
    // if (
    //   typeof obj === 'object' &&
    //   obj.hasOwnProperty('numberOfSubdomains') &&
    //   obj.hasOwnProperty('numberOfActiveSubdomains') &&
    //   obj.hasOwnProperty('array') &&
    //   Array.isArray(obj.array)
    // ) {
    //   // Check if the values are of the expected types
    //   if (
    //     typeof obj.numberOfSubdomains === 'number' &&
    //     typeof obj.numberOfActiveSubdomains === 'number'
    //   ) {
        return true;
    //   }
    // }
    // return false;
  }


module.exports = vulnfunctions