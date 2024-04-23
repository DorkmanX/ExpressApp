const express = require('express')
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

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
};

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
};

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
    auth: {
      user: 'kamil.rzezniczek@gmail.com',
      pass: process.env.API_EMAIL_PASSWORD
    }
  });

  var mailOptions = {
    from: 'kamil.rzezniczek@gmail.com',
    to: receiverEmail,
    subject: 'Account activation Express js App',
    text: `Please click on this link to activate your account: http:localhost:3000/registerconfirm?token=${generatedToken}`
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

  const userToRegister = new User({ 
    login: req.body.login,
    password: req.body.password,
    token: '',
    email: req.body.email,
    name: req.body.name,
    surname: req.body.surname,
    activated: false,
    resetPassword: false
  });

  const newUser = await userToRegister.save()    
  .then(async () => {
    let activationToken = await CreateJWT(newUser._id,req.body.login,24);
    await SendEmail(req.body.email,activationToken);
    res.status(201).send('User registered sucessfully! Please activate your account by clicking on link in email sended to your account');
  })
  .catch(error => res.status(500).send("Error during register user in database, reason: " + error));
})

app.post('/registerconfirm', async(req,res) => {

  var tokenVerification = await VerifyJWT(req.query.token);
  if(tokenVerification.result) {
    const filters = {};
    if (tokenVerification.userDetails.id) {
      filters._id = tokenVerification.userDetails.id;
    }
    if (tokenVerification.userDetails.login) {
      filters.login = tokenVerification.userDetails.login;
    }
    var user = await MyModel.findOne(filters);
    if(!user){
      req.status(404).send("User dont exist");
    }
    user.activated = true;
    await user.save();
    req.status(200).send("Your account has been confirmed succesfully. Welcome.");
  } 
  else
    req.status(404).send("Token is invalid");
})

app.post('/login', async(req,res) => {
    let login = req.body.login;
    let password = req.body.password;

    
})

app.get('/getusers', VerifyJWT, async (req, res) => {
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