// SUMMARY FROM 15:44

import express from 'express'
import bodyParser from 'body-parser'
import cors from 'cors'
import mongoose from 'mongoose'
import crypto from 'crypto'
import bcrypt from 'bcrypt-nodejs'

const mongoUrl = process.env.MONGO_URL || "mongodb://localhost/auth"
mongoose.connect(mongoUrl, { userNewUrlParser: true, useUnifiedTopology: true })
mongoose.Promise = Promise

const User = mongoose.model('User', {
  name: {
    type: String,
    unique: true
  },
  email: {
    type: String,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  accessToken: {
    type: String,
    default: () => crypto.randomBytes(128).toString('hex')
  }
})

// WE USE THIS FUNCTION TO PROTECT OUR SECRET'S ENDPOINT.
const authenticateUser = async (req, res, next) => {
  const user = await User.findOne({ accessToken: req.header('Authorization') })
  if (user) {
    // Attach the user object to the request.
    req.user = user
    next()
  } else {
    res.status(401).json({ loggedOut: true })
  }
}

//   PORT=9000 npm start
const port = process.env.PORT || 8080
const app = express()

// Add middlewares to enable cors and json body parsing
app.use(cors())
app.use(bodyParser.json())

// Start defining your routes here
app.get('/', (req, res) => {
  res.send('Hello world')
})

app.post('/users', async (req, res) => {
  try {
    // Retrieve the name, email and password from the JSON request body.
    const { name, email, password } = req.body
    // Create a new user from the Mongoose User model, using this information.
    // Store the hashed value in the database
    // DO NOT STORE PLAINTEXT PASSWORDS – that's what bcrypt does.
    const user = new User({ name, email, password: bcrypt.hashSync(password) })
    // Save to database
    user.save()
    // "id: user._id" is the Mongo internal ID. Access token is their 'pass' to get into any restricted endpoint.
    res.status(201).json({ id: user._id, accessToken: user.accessToken })
  } catch (err) {
    res.status(400).json({ message: 'Could not create user', errors: err.errors })
  }
})
app.get('/secrets', authenticateUser)
app.get('/secrets', (req, res) => {
  // This will be open to anyone who can make a GET request.
  res.json({ secret: 'This is a super secret message' })
})

app.post('/sessions', async (req, res) => {
  const user = await User.findOne({ email: req.body.email })
  // req.body.password is the cleartext password from the request, and user.password is the hashed password in the database.
  if (user && bcrypt.compareSync(req.body.password, user.password)) {
    res.json({ userId: user._id, accessToken: user.accessToken })
  } else {
    res.json({ notFound: true })

  }
})

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`)
})
