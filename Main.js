const express = require('express')
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');

const app = express()
const port = 3000

//database related functions

async function ConnectToDatabase () {
    try {
        await mongoose.connect('mongodb://127.0.0.1:27017/expressdb', {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            useCreateIndex: true
        });
        dotenv.config();
        console.log('MongoDB connection established successfully!');
    }
    catch(error) {
        console.log("Failed connect to database with error: " + toString(error));
        process.exit(1);
    }
};

//verification functions

function VerifyJWT (req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send('Unauthorized');
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.API_SECRET_KEY);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(403).send('Forbidden');
  }
};

//models and schemas
const userSchema = new mongoose.Schema({ 
    login: String, 
    password: String, 
    token: String,
    name: String, 
    surname: String, 
    activated: Boolean,
    resetPassword: Boolean
 });

const User = mongoose.model('User', userSchema,'Users');

//endpoints

app.get('/getusers', VerifyJWT, async (req, res) => {
    var filters = req.params.filters;
    var body = req.body;
    var queryParam = req.query;

    const newUser = new User({ 
        login: req.body.login,
        password: req.body.password,
        token: '',
        name: req.body.name,
        surname: req.body.surname,
        activated: false,
        resetPassword: false
    });

    await User.create(newUser)
    .then(() => res.send('User added sucessfully!'))
    .catch(error => console.log("Error during save to database, reason: " + error));
})

app.listen(port, async () => {
  console.log(`Express js app started at port: ${port}`);
  console.log(`Started attempt to connect to database`);
  await ConnectToDatabase();
})