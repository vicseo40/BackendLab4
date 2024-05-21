const express = require("express")
const app = express()
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
require('dotenv').config()
const { initializeDatabase, getUserById } = require('./database')

app.set('view-engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(express.json())

app.listen(8000)

var currentKey = ""
var currentPassword = ""

// Initialize the db
initializeDatabase()

// Default route is identify
app.get('/', (req, res) => {
    res.redirect("/identify")
})

// Route for identify
app.get('/identify', (req, res) => {
    res.render('lab4/identify.ejs')
})


// Route for the identify post
app.post('/identify', (req, res) => {
    const { userID, password } = req.body

    getUserById(userID, (err, user) => {
        if (err) {
            return res.status(500).send("Server error")
        }
        if (!user || !bcrypt.compareSync(password, user.password)) {
            return res.status(401).send("Invalid credentials")
        }

        const token = jwt.sign({ userID: user.userID, role: user.role }, process.env.ACCESS_TOKEN_SECRET)
        currentKey = token
        currentPassword = password
        res.redirect("/start")
    })
})

// Route for start
app.get('/start', authenticateToken, (req, res) => {
    res.render('lab4/start.ejs')
})

// Route for admin
app.get('/admin', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).redirect('/identify')
    }
    getAllUsers((err, users) => {
        if (err) {
            return res.status(500).send("Server error")
        }
        res.render('lab4/admin.ejs', { users: users })
    })
})

// Route for student1
app.get('/student1', authenticateToken, (req, res) => {
    if (req.user.role !== 'student1' && req.user.role !== 'teacher' && req.user.role !== 'admin') {
        return res.status(403).redirect('/identify')
    }
    res.render('lab4/student1.ejs')
})

// Route for student2
app.get('/student2', authenticateToken, (req, res) => {
    if (req.user.role !== 'student2' && req.user.role !== 'teacher' && req.user.role !== 'admin') {
        return res.status(403).redirect('/identify')
    }
    res.render('lab4/student2.ejs')
})

// Route for teacher
app.get('/teacher', authenticateToken, (req, res) => {
    if (req.user.role !== 'teacher' && req.user.role !== 'admin') {
        return res.status(403).redirect('/identify')
    }
    res.render('lab4/teacher.ejs')
})


// Logout if I want
app.get('/logout', (req, res) => {
    currentKey = ""
    res.redirect('/identify')
})

// Authenticaiton using jwt
function authenticateToken(req, res, next) {
    if (!currentKey) {
        return res.redirect("/identify")
    }

    try {
        const user = jwt.verify(currentKey, process.env.ACCESS_TOKEN_SECRET)
        req.user = user
        next()
    } catch (err) {
        res.redirect("/identify")
    }
}

//From pre-task
app.get('/granted', authenticateToken, (req, res) => {
    res.render("lab4/start.ejs")
})


/*

Practice code

var currentKey = ""
var currentPassword= ""

app.get('/', (req, res) => {
    res.redirect("/identify")
})

app.post('/identify', (req,res) => {
    const username = req.body.password
    const token = jwt.sign(username, process.env.ACCESS_TOKEN_SECRET)
    currentKey = token
    currentPassword = username
    res.redirect("/granted")
})

app.get('/identify', (req, res) => {
    res.render('lab4/identify.ejs')
})

function authenticateToken(req,res,next){
    console.log("We are in the authentication control function")
    if(currentKey == ""){
        res.redirect("/identify")
    }else if(jwt.verify(currentKey,process.env.ACCESS_TOKEN_SECRET)){
        next()
    }else{
        res.redirect("/identify")
    }
}

app.get('/granted', authenticateToken, (req,res) => {
    res.render("lab4/start.ejs")
})

app.listen(8000)
*/