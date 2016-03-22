'use strict';

var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var bcrypt = require('bcrypt');
var jwt = require('jsonwebtoken');


var userSchema = new Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  }
});

userSchema.pre('save', function(next) {
  this.password = bcrypt.hashSync(this.password, bcrypt.genSaltSync(10));
  next();
})

userSchema.methods.compareHash = function(password) {
  return bcrypt.compareSync(password, this.password);
}

userSchema.methods.generateToken = function() {
  jwt.sign({ _id: this._id}, 'CHANGE ME');
}

module.exports = mongoose.model('User', userSchema);


