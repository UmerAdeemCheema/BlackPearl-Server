const express = require("express");
const morgan = require("morgan");
const cors = require("cors");
const connectDB = require("./config/db");
//const passport = require("passport");
const bodyParser = require("body-parser");
const routes = require('./routes/rroutes')

connectDB()

var http = require("http");
const app = express();

if(process.env.NODE_ENV === 'development'){
    app.use(morgan('dev'))
}

const port = process.env.PORT || 5000;

app.use(cors());
//middleware
// app.use("/uploads", express.static("uploads"))
app.use(express.json());
app.use(bodyParser.urlencoded({extended:false}));
app.use(bodyParser.json());

app.use(routes);
// app.use(passport.initialize());
//require('./config/passport')(passport);

app.listen(port, console.log(`Server running in ${process.env.NODE_ENV} mode on port ${port}`))



// npm install nodemon passport passport-jwt socket.io morgan mongoose jwt-simple express dotenv cross-env cors connect-mongo body-parser bcrypt