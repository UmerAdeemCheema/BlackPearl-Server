const mongoose = require("mongoose");
const dbconfig = require("./dbconfig");

const connectDB = async() =>{
    try{
        const conn = await mongoose.connect(dbconfig.database,{
            useNewUrlParser:true,
            useUnifiedTopology:true
        })
        console.log("MongoDB connected: ",conn.connection.host)
    }
    catch(error){
        console.log(error)
        process.exit(1)
    }
}

module.exports = connectDB