
var inquirer = require('inquirer');
var chalk = require('chalk');

var utils = require('./utils');

exports.generateEncryptionKey = function(passphrase, salt) {
  return utils.sha512Hash(passphrase, salt);
}

var inquirerGetPassphrase = function(options, callback) {
  var questions = [];
  questions.push({
    type: 'password',
    name: 'passphrase',
    message: chalk.magenta('Please enter passphrase:')
  });

  if (options.verify) {
    questions.push({
      type: 'password',
      name: 'verify_passphrase',
      message: chalk.magenta('Please re-enter passphrase:')
    });
  }
    
  inquirer.prompt(questions).then(function(answers) {
    if (options.verify && answers.passphrase != answers.verify_passphrase) {
      console.log('Passphrases don\'t match!');
      return callback(new Error('Passphrases don\'t match!'));
    }
    return callback(null, answers.passphrase);
  });
}

exports.getInputPassphrase = function(options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }
  
  return inquirerGetPassphrase(options, callback);
}

var inquirerGetSalt = function(options, callback) {
  var questions = [];
  questions.push({
    type: 'password',
    name: 'salt',
    message: chalk.magenta('Please enter salt:')
  });

  inquirer.prompt(questions).then(function(answers) {
    return callback(null, answers.salt);
  });
}

exports.getInputSalt = function(options, callback) {
  if (typeof options == 'function') {
    callback = options;
    options = {};
  }
  
  return inquirerGetSalt(options, callback);
}
