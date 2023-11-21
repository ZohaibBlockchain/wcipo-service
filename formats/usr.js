// models/user.js

import { Schema, model } from 'mongoose';

// Define the profile schema
const profileSchema = new Schema({
  email: { unique: true, type: String },
  password: String,
  accountStatus: Boolean,
  fullName: String,
  address: String,
  phone: String,
  countryCode: String
});

// Define the work schema
const workSchema = new Schema({
  registrationNumber: String,
  typeOfWork: String,
  title: String,
  requestDate: String,
  certificate: String,
  statusOfRequest: String,
  PackageName: String,
  Recipt: String,
  paidAmount:String
});

// Combine the profile and work schemas into the user schema
const userSchema = new Schema({
  profile: { type: profileSchema, required: true },
  works: [workSchema]
});

// Export the user model
export default model('User', userSchema);