const express = require('express')
const mongoose = require('mongoose');
mongoose.connect('mongodb://127.0.0.1:27017/expressdb');

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

const app = express()
const port = 3000

app.get('/', (req, res) => {
    
    const newUser = new User({ 
        login: 'rzeznikx',
        password: '1234abcd',
        token: '',
        name: 'Marek',
        surname: 'Rzezniczek',
        activated: false,
        resetPassword: false
    });
    newUser.save().then(() => res.send('User added sucessfully!'));
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})