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

app.get('/', (req, res) => {
    res.redirect("/identify")
})

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

app.get('/identify', (req, res) => {
    res.render('lab4/identify.ejs')
})

app.get('/start', authenticateToken, (req, res) => {
    res.render('lab4/start.ejs')
})

app.get('/admin', authenticateToken, (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).redirect('/identify')
    }
    res.render('lab4/admin.ejs')
})

app.get('/granted', authenticateToken, (req, res) => {
    res.render("lab4/start.ejs")
})


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