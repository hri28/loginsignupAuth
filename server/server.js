import express from "express"; //using type = module in package.json we can simply use the import statement instead of using require
console.log('I am working');

const app = express()

//dotenv
import dotenv from "dotenv"
dotenv.config()

//db
import connectDB from './db/connect.js'

//route
import authRoute from './routes/authRoute.js'

//morgan
import morgan from 'morgan'
if(process.env.NODE_ENV !== 'production'){
    app.use(morgan('dev'))
}

app.use(express.json())
app.get('/',(req,res) =>{
    res.send('Welcome')
})

app.get('/api/v1',(req,res)=>{
    res.json({msg:'Here'})
})

app.use('/api/v1/auth',authRoute)
const port = process.env.PORT || 5004

const start = async() =>{
    await connectDB(process.env.MONGO_URL)
    app.listen(port,()=>{
        console.log(`running on ${port}`);
    })
}
start()