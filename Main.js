const express = require('express')
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');

const app = express()
const port = 3000

//global parsing of jsons
app.use(bodyParser.json());

//database related functions

async function ConnectToDatabase () {
    try {
        await mongoose.connect('mongodb://127.0.0.1:27017/expressdb');
        dotenv.config();
        console.log('MongoDB connection established successfully!');
    }
    catch(error) {
        console.log("Failed connect to database with error: " + error);
        process.exit(1);
    }
};

//verification functions

async function CreateJWT(id,login,timeExpiresH) {
    const credentials = {
        login: login,
        id: id
    };
    const token = jwt.sign(credentials, process.env.API_SECRET_KEY, { expiresIn: `${timeExpiresH}h` });
    return token;
}

function VerifyJWT(token) {
  try {
    const decoded = jwt.verify(token, process.env.API_SECRET_KEY);
    return { result: true, userDetails: decoded};
  } catch (error) {
    return { result: false, userDetails: error};
  }
}

function VerifyJWTMiddleware (req, res, next) {
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
}

async function createHashPassword(password) {
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);
    return hash;
}

async function checkPasswordCorrect(plainTextPassword, hashedPassword) {
    return await bcrypt.compare(plainTextPassword, hashedPassword);
}

//sending emails

async function SendEmail(receiverEmail,generatedToken) {
  var transporter = nodemailer.createTransport({
    service: 'gmail',
    secure: false,    
    host: "smtp.gmail.com",
    port: 587,
    auth: {
      user: 'kamil.rzezniczek@gmail.com',
      pass: process.env.API_EMAIL_PASSWORD
    }
  });

  var mailOptions = {
    from: 'kamil.rzezniczek@gmail.com',
    to: receiverEmail,
    subject: 'Account activation Express js App',
    html: `<span>Please click on this link to activate your account:</span> <a href="http://localhost:3000/registerconfirm?token=${generatedToken}">Click to activate</a>`
  };
  
  transporter.sendMail(mailOptions, function(error, info){
    if (error) {
      console.log(error);
    } else {
      console.log('Email sent: ' + info.response);
    }
  });
}


//models and schemas
const userSchema = new mongoose.Schema({ 
    login: String, 
    password: String, 
    email: String,
    token: String,
    name: String, 
    surname: String, 
    activated: Boolean,
    resetPassword: Boolean
 });

const User = mongoose.model('User', userSchema,'Users');

//endpoints
app.post('/register', async(req,res) => {

  const data = req.body;

  const userToRegister = new User({ 
    login: data.login,
    password: await createHashPassword(data.password),
    token: '',
    email: data.email,
    name: data.name,
    surname: data.surname,
    activated: false,
    resetPassword: false
  });

  await User.create(userToRegister)
  .then(async (insertedUser) => {
    let activationToken = await CreateJWT(insertedUser._id,insertedUser.login,24);
    await SendEmail(insertedUser.email,activationToken);
    res.status(201).send('User registered sucessfully! Please activate your account by clicking on link in email sended to your account');
  })
  .catch(error => res.status(500).send("Error during register user in database, reason: " + error));
})

app.get('/registerconfirm', async(req,res) => {

  var tokenVerification = await VerifyJWT(req.query.token);
  if(tokenVerification.result) {
    const filters = {};
    if (tokenVerification.userDetails.id) {
      filters._id = tokenVerification.userDetails.id;
    }
    if (tokenVerification.userDetails.login) {
      filters.login = tokenVerification.userDetails.login;
    }

    User.updateOne(
      filters,
      { $set: { ["activated"]: true } }
    )
    .then(result => {
      console.log(result);
      res.status(200).send("Your account has been confirmed succesfully. Welcome.");
    })
    .catch(error => {
      console.error(error);
      res.status(500).send("DB error");
    });
  } 
  else
    res.status(404).send("Token is invalid");
})

app.get('/resetpassword', async(req,res) => {
  const email = req.query.email;
  
  await User.findOne( { "email" : email })  
  .then(async (user) => {
    console.log("User password reset enable");
    await User.updateOne(
      { "email" : email },
      { $set: { ["resetPassword"]: true } }
    ).then(async (result) => {
      console.log(result);
      res.status(200).send(await CreateJWT(user._id,user.login,1)); //send access token for front end to update password
    })
    .catch(error => {
      console.error(error);
      res.status(500).send("DB error");
    });
  })
  .catch(error => {
    console.error(error);
    res.status(404).send("User with this email dont exist");
  });
})

app.post('/resetconfirm', async(req,res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send('Unauthorized');
  }

  const token = authHeader.split(' ')[1];
  var tokenVerification = await VerifyJWT(token);

  if(tokenVerification.result) {
    const filters = {};
    if (tokenVerification.userDetails.id) {
      filters._id = tokenVerification.userDetails.id;
    }
    if (tokenVerification.userDetails.login) {
      filters.login = tokenVerification.userDetails.login;
    }

    const body = req.body;

    if(body.newpass !== body.newpass2){
      res.status(404).send("Passwords are different!");
    }

    const passwordHash = await createHashPassword(body.newpass);

    await User.updateOne(
      filters,
      { $set: { ["resetPassword"]: false, ["password"] : passwordHash } }
    )
    .then(result => {
      console.log(result);
      res.status(200).send("Your password changed successfully.");
    })
    .catch(error => {
      console.error(error);
      res.status(500).send("DB error");
    });
  } 
  else
    res.status(404).send("Token is invalid");
})

app.post('/login', async(req,res) => {
    let login = req.body.login;
    let password = req.body.password;

    
})

app.get('/getusers', VerifyJWTMiddleware, async (req, res) => {
  const filters = {};
  if (req.query.name) {
    filters.name = req.query.name; // Filter by name
  }
  if (req.query.age) {
    filters.age = req.query.age; // Filter by age (can use comparison operators like $gt, $lt)
  }
  const documents = await MyModel.find(filters);
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
    .then(() => res.json('User added sucessfully!'))
    .catch(error => console.log("Error during save to database, reason: " + error));
})

app.listen(port, async () => {
  console.log(`Express js app started at port: ${port}`);
  console.log(`Started attempt to connect to database`);
  await ConnectToDatabase();
})