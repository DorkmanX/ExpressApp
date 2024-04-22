const express = require('express');
const app = express();
const jwt = require('jsonwebtoken'); // For token verification (explained later)
const { secret } = require('./config'); // Load your secret key from a secure location

const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send('Unauthorized');
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, secret);
    req.user = decoded; // Attach decoded user data to the request
    next();
  } catch (error) {
    res.status(403).send('Forbidden');
  }
};

app.get('/protected-resource', verifyJWT, (req, res) => {
  // Access user data from req.user (if token is valid)
  res.send('Welcome, authorized user!');
});