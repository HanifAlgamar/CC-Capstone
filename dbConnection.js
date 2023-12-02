const mysql = require('mysql');

const db = mysql.createConnection({
    host : "localhost",
    user : "root", 
    database : "db_user",
    password : ""
})
    db.connect((err) => {
        if(err) throw err;
        console.log("Database Connected");
    })

module.exports = db;