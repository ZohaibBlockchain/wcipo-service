// models/user.js
import { mongoose } from 'mongoose';

const profileSchema = new mongoose.Schema({
  email: { unique: true, type: String },
  password: String,
  accountStatus: Boolean,
  fullName: String,
  address: String,
  phone: String,
  countryCode: String
});


const workSchema = new mongoose.Schema({
  registrationNumber: String,
  typeOfWork: String,
  title: String,
  requestDate: String,
  certificate: String,
  statusOfRequest: String,
  PackageName: String,
  Recipt: String
});




const userSchema = new mongoose.Schema({
  profile: profileSchema,
  works: [workSchema]
});



// Create models from the schemas
const Profile = mongoose.model('Profile', profileSchema);
const User = mongoose.model('User', userSchema);

// Export the models if you are using modules
export default { User, Profile };



// export default mongoose.model('User', userSchema);

