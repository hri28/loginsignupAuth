import mongoose from 'mongoose'
import validator from 'validator'
import bcryptjs from 'bcryptjs'
import jwt from 'jsonwebtoken'

const userSchema = new mongoose.Schema({
    name:{
        type:String,
        required:[true,'Please provide name'],
        minlength:4,
        maxlength:25,
        trim:true
    },
    email:{
        type:String,
        required:true,
        validate:{
            validator:validator.isEmail,
            message:'Please provide a valid email address'
        },
        unique:true
    },
    password:{
        type:String,
        required:[true, 'Please provide your password'],
        minlength:6,
        select:false
    }
})
//before saving userschema hash the password
/*a salt is random data used as an additional input to a one way function
that hashes data or passwords it guarantees a unique output
*/
userSchema.pre('save', async function(){
    const salt = await bcryptjs.genSalt(10)
    this.password = await bcryptjs.hash(this.password, salt)
})

//jwt
userSchema.methods.createJWT = function(){
    return jwt.sign({userId:this._id},process.env.JWT_SECRET,{expiresIn:process.env.JWT_LIFETIME})
}

//check if passwords match
userSchema.methods.comparePassword = async function(candidate){
    const isMatch = await bcryptjs.compare(candidate, this.password)
    return isMatch
}

export default mongoose.model('User', userSchema)