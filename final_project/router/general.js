const express = require('express');
let books = require("./booksdb.js");
let isValid = require("./auth_users.js").isValid;
let users = require("./auth_users.js").users;
const axios = require('axios');
const public_users = express.Router();


public_users.post("/register", (req,res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }

  if (users[username]) {
    return res.status(400).json({ message: "Username already exists" });
  }

  users[username] = { password };
  return res.status(200).json({ message: "User registered successfully" });
  return res.status(300).json({message: "Yet to be implemented"});
});

public_users.get('/', async (req, res) => {
  try {
      const response = await axios.get('http://localhost:5000/books');
      const books = response.data;
      res.status(200).json(books);
  } catch (error) {
      res.status(500).json({ message: "Error fetching books", error: error.message });
  }
});

// Get book details based on ISBN
public_users.get('/isbn/:isbn', (req, res) => {
  const isbn = req.params.isbn;
  axios.get(`http://localhost:5000/books/${isbn}`)
      .then(response => {
          const book = response.data;
          res.status(200).json(book);
      })
      .catch(error => {
          res.status(404).json({ message: "Book not found", error: error.message });
      });
});
  
// Get book details based on author
public_users.get('/author/:author', function (req, res) {
  const author = req.params.author;
  const booksByAuthor = Object.values(books).filter(book => book.author === author);
  if (booksByAuthor.length > 0) {
      res.send(booksByAuthor);
  } else {
      res.status(404).json({ message: "Books by this author not found" });
  }
});

// Get all books based on title
public_users.get('/title/:title', function (req, res) {
  const title = req.params.title;
  const booksByTitle = Object.values(books).filter(book => book.title === title);
  if (booksByTitle.length > 0) {
      res.send(booksByTitle);
  } else {
      res.status(404).json({ message: "Books with this title not found" });
  }
});

//  Get book review
public_users.get('/review/:isbn',function (req, res) {
  //Write your code here
  const isbn = req.params.isbn;
  const book = books[isbn];
  if (book && book.reviews) {
    res.send(book.reviews);
  } else {
    res.status(404).json({ message: "No reviews found for this book" });
  }
  return res.status(300).json({message: "Yet to be implemented"});
});

module.exports.general = public_users;
