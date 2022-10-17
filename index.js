const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const app = express();
require("dotenv").config();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
      extended: true
}));

require('./mongodb').init()
const toDo = require('./mongodb/todo.model')
const Admin = require('./mongodb/admin.model')

//==========================JWT Token ==================================================
      const jwt = require('jsonwebtoken');
      const bcrypt = require('bcryptjs');
      app.post('/saveAdminToken', function (req, res) {
            let hashedPassword = bcrypt.hashSync(req.body.password, 8);
            let adminAuth = new Admin({
                  username: req.body.username,
                  password: hashedPassword
            })
            adminAuth.save((err, auth) => {
                  if (err) {
                        res.status(500).json({
                              err
                        });
                  } else {
                        let token = jwt.sign({ id: auth.id, username: auth.username, password: auth.password }, '12@kalra#45', {
                              expiresIn: 86400 // expires in 24 hours
                        });
                        res.status(200).send({ message: 'Admin auth generated', auth: true, token: token });
                  }
            });
      });

      app.post('/generateToken', function (req, res) {
            let authid = req.body.id;
            let plainPassword = req.body.password;
            Admin.findById(authid, (err, admin) => {
                  if (err) {
                        res.status(500).json({
                              err
                        });
                  } else {
                        bcrypt.compare(plainPassword, admin.password).then(function (result) {
                              if (result == true) {
                                    let token = jwt.sign({ id: admin.id, username: admin.username, password: admin.password }, process.env.JWTKEY, {
                                          expiresIn: 86400 // expires in 24 hours
                                    });
                                    res.status(200).send({ message: 'Auth-Token', auth: true, token: token });
                              } else {
                                    res.status(200).send({ message: 'Invalid user', auth: false });
                              }

                        });

                  }
            });
      });

      app.get('/verifyJwtToken', function (req, res) {
            var token = req.headers['x-access-token'];
            if (!token) return res.status(401).send({ auth: false, message: 'No token provided.' });
            let authid = '634db2bcabea8797c32bfb9c';
            Admin.findById(authid, (err, auth) => {
                  if (err) {
                        res.status(500).json({
                              err
                        });
                  } else {
                        let secret = process.env.JWTKEY
                        jwt.verify(token, secret, function (err, decoded) {
                              if (err) return res.status(500).send({ auth: secret, message: 'Failed to authenticate token.' });
                              res.status(200).send(decoded);
                        });
                  }
            })
      });

      function authenticateToken(req, res, next) {
            var token = req.headers['x-access-token'];
            if (token == null) return  res.status(401).send({ auth: false, message: 'Failed to authenticate.' });
            let secret = process.env.JWTKEY
            jwt.verify(token, secret, function (err, decoded) {
                  if (err) return res.status(403).send({ auth: true, message: 'Failed to authenticate token.' });
                  next()
            });
      }
//======================= END ==============================================================


//Create To-Do
app.post('/', authenticateToken,(req, res) => {
      const { title, description, createdBy } = req.body;
      let toDoAdd = new toDo({
            title: title,
            description: description,
            createdBy: createdBy
      });
      toDoAdd.save((err, todo) => {
            if (err) {
                  res.status(500).json({
                        err
                  });
            } else {
                  res.status(201).json({
                        message: 'To-Do has been created',
                        todo
                  });
            }
      });
});


//View To-Do
app.get('/', authenticateToken,(req, res) => {
      toDo.find({}, (err, toDos) => {
            if (err) {
                  res.status(500).json({
                        err
                  });
            } else {
                  res.status(200).json({
                        message: 'All ToDos',
                        toDos
                  });
            }
      });
});

//View Single To-Do Record
app.get('/:todo_id', authenticateToken,(req, res) => {
      const { todo_id } = req.params;
      toDo.findById(todo_id, (err, toDo) => {
            if (err) {
                  res.status(500).json({
                        err
                  });
            } else {
                  res.status(200).json({
                        message: 'To-Do',
                        toDo
                  });
            }
      });
});


//Update Single To-Do
app.patch('/:todo_id', authenticateToken,(req, res) => {
      const { todo_id } = req.params;
      const { title, description, createdBy } = req.body;
      toDo.findByIdAndUpdate(todo_id, {
            title: title,
            description: description,
            createdBy: createdBy
      }, (err, toDo) => {
            if (err) {
                  res.status(500).json({
                        err
                  });
            } else {
                  res.status(200).json({
                        message: 'To-Do updated',
                        toDo
                  });
            }
      });
});

//Remove Single To-Do
app.delete('/:todo_id', authenticateToken,(req, res) => {
      const { todo_id } = req.params;
      toDo.findByIdAndDelete(todo_id, (err, toDo) => {
            if (err) {
                  res.status(500).json({
                        err
                  });
            } else {
                  res.status(200).json({
                        message: 'To-Do has been removed',
                        toDo
                  });
            }
      });
});


app.listen(process.env.PORT, () => {
      console.log('Server listening on ' + process.env.PORT);
});