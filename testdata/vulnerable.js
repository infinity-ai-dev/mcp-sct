const { exec } = require("child_process");
const mysql = require("mysql");

// SQL Injection - BAD
function getUser(userId) {
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  return db.query(query);
}

// XSS - BAD
function renderContent(userInput) {
  document.getElementById("output").innerHTML = userInput;
  document.write(userInput);
}

// Command Injection - BAD
function runCommand(userInput) {
  exec(`ls ${userInput}`);
}

// Prototype Pollution - BAD
function mergeConfig(req) {
  Object.assign(config, req.body);
}

// Hardcoded Secret - BAD
const API_KEY = "sk-1234567890abcdef1234567890abcdef";

// dangerouslySetInnerHTML - BAD
function Component({ data }) {
  return <div dangerouslySetInnerHTML={{ __html: data }} />;
}

// Safe parameterized query - GOOD (should not trigger)
function getUserSafe(userId) {
  return db.query("SELECT * FROM users WHERE id = $1", [userId]);
}
