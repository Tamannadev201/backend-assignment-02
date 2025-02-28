const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const app = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('/User/tamannatabassum/Desktop/Ostad batch 8/Backend Assignment 2/models/User'); // import User model
const Portfolio = require('./models/Portfolio'); // import Portfolio model

dotenv.config();


app.use(express.json()); 
app.use(cors()); 


mongoose.connect(process.env.DB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.log('MongoDB connection error:', err));


app.get('/', (req, res) => {
  res.send('Server is running');
});


app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    const user = new User({
      name,
      email,
      password: await bcrypt.hash(password, 10),  // Encrypt the password
    });
    await user.save();
    res.status(201).send('User registered successfully');
  } catch (err) {
    res.status(500).send('Error registering user');
  }
});


app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).send('User not found');
    }
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).send('Invalid credentials');
    }
    
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).send('Error logging in');
  }
});


const auth = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(403).send('Access denied');
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).send('Invalid token');
  }
};


app.post('/api/portfolio', auth, async (req, res) => {
  const { title, description, img, codelink, livelink } = req.body;
  
  try {
    const portfolio = new Portfolio({
      userId: req.userId, // User ID from the token
      title,
      description,
      img,
      codelink,
      livelink
    });
    await portfolio.save();
    res.status(201).send('Portfolio created');
  } catch (err) {
    res.status(500).send('Error creating portfolio');
  }
});



app.get('/api/portfolio', auth, async (req, res) => {
  try {
    const portfolios = await Portfolio.find({ userId: req.userId });
    res.json(portfolios);
  } catch (err) {
    res.status(500).send('Error fetching portfolios');
  }
});



app.put('/api/portfolio/:id', auth, async (req, res) => {
  try {
    const portfolio = await Portfolio.findByIdAndUpdate(
      req.params.id, 
      { ...req.body },
      { new: true }
    );
    if (!portfolio) {
      return res.status(404).send('Portfolio not found');
    }
    res.json(portfolio);
  } catch (err) {
    res.status(500).send('Error updating portfolio');
  }
});



app.delete('/api/portfolio/:id', auth, async (req, res) => {
  try {
    const portfolio = await Portfolio.findByIdAndDelete(req.params.id);
    if (!portfolio) {
      return res.status(404).send('Portfolio not found');
    }
    res.send('Portfolio deleted');
  } catch (err) {
    res.status(500).send('Error deleting portfolio');
  }
});



const port = process.env.PORT || 5001;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
