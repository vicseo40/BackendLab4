const sqlite3 = require('sqlite3').verbose()
const bcrypt = require('bcrypt')
const fs = require('fs')

if (fs.existsSync('users.db')) {
    fs.unlinkSync('users.db')
}

const db = new sqlite3.Database('users.db')

function initializeDatabase() {
    db.serialize(() => {
        db.run('CREATE TABLE IF NOT EXISTS Users (userID TEXT PRIMARY KEY, role TEXT, name TEXT, password TEXT)')
        
        const stmt = db.prepare('INSERT INTO Users (userID, role, name, password) VALUES (?, ?, ?, ?)')
        
        const users = [
            { userID: 'id1', role: 'student1', name: 'user1', password: 'password' },
            { userID: 'id2', role: 'student2', name: 'user2', password: 'password2' },
            { userID: 'id3', role: 'teacher', name: 'user3', password: 'password3' },
            { userID: 'admin', role: 'admin', name: 'admin', password: 'admin' }
        ]

        users.forEach(user => {
            stmt.run(user.userID, user.role, user.name, bcrypt.hashSync(user.password, 10))
        })

        stmt.finalize()
    })
}

function getUserById(userID, callback) {
    db.get('SELECT * FROM Users WHERE userID = ?', [userID], (err, user) => {
        callback(err, user)
    })
}

function getAllUsers(callback) {
    db.all('SELECT * FROM Users', [], (err, rows) => {
        callback(err, rows)
    })
}

module.exports = {
    db,
    initializeDatabase,
    getUserById,
    getAllUsers
}
