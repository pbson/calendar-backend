if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const express = require('express')
const app = express()
const server = require('http').createServer(app)
const fileUpload = require('express-fileupload');
const bodyParser=require('body-parser');
const cors = require('cors')

//cors
app.use(cors())
app.use(express.json());
app.use(bodyParser.json());
app.use(fileUpload({
  useTempFiles: true,
  tempFileDir: '/tmp/'
}));
app.use(express.static(__dirname + '/public/'));

app.set("view engine", "ejs"); 

server.listen(process.env.PORT || 3000);

//Mongoose connect
const mongoose = require('mongoose')

mongoose.connect(process.env.DATABASE_URL, {useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false, 'useCreateIndex':true})

const db = mongoose.connection
db.on('error',error => console.log(error));
db.on('open',() => console.log('Connected to mongoose'));

//Import Routes
const authRouter = require('./api/routes/auth')

app.use('/auth', authRouter);
