const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const db = new sqlite3.Database('users.db');

function initializeDatabase() {
    db.serialize(() => {
        db.run('CREATE TABLE IF NOT EXISTS Users (userID TEXT PRIMARY KEY, role TEXT, name TEXT, password TEXT)');
        
        const stmt = db.prepare('INSERT INTO Users (userID, role, name, password) VALUES (?, ?, ?, ?)');
        
        const users = [
            { userID: 'id1', role: 'student', name: 'user1', password: 'password' },
            { userID: 'id2', role: 'student', name: 'user2', password: 'password2' },
            { userID: 'id3', role: 'teacher', name: 'user3', password: 'password3' },
            { userID: 'admin', role: 'admin', name: 'admin', password: 'admin' }
        ];

        users.forEach(user => {
            stmt.run(user.userID, user.role, user.name, bcrypt.hashSync(user.password, 10));
        });

        stmt.finalize();
    });
}

function getUserById(userID, callback) {
    db.get('SELECT * FROM Users WHERE userID = ?', [userID], (err, user) => {
        callback(err, user);
    });
}

module.exports = {
    initializeDatabase,
    getUserById
};
