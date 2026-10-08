import mongoose from 'mongoose';
const userSchema = new mongoose.Schema({ username:{type:String,unique:true,required:true}, email:{type:String,unique:true,required:true}, passwordHash:String, publicKey:String, encryptedPrivateKey:Object }, {timestamps:true});
const conversationSchema = new mongoose.Schema({ members:[{type:mongoose.Schema.Types.ObjectId,ref:'User',required:true}], lastMessageAt:Date },{timestamps:true});
const messageSchema = new mongoose.Schema({ conversation:{type:mongoose.Schema.Types.ObjectId,ref:'Conversation',required:true}, sender:{type:mongoose.Schema.Types.ObjectId,ref:'User',required:true}, kind:{type:String,enum:['text','image'],required:true}, encrypted:{type:Object,required:true}, wrappedKeys:{type:Object,required:true}, metadata:Object, deletedFor:[{type:mongoose.Schema.Types.ObjectId,ref:'User'}], deletedForEveryone:{type:Boolean,default:false}, sentAt:{type:Date,default:Date.now} });
const eventSchema = new mongoose.Schema({ actor:mongoose.Schema.Types.ObjectId, type:String, detail:String },{timestamps:true});
export const User=mongoose.model('User',userSchema); export const Conversation=mongoose.model('Conversation',conversationSchema); export const Message=mongoose.model('Message',messageSchema); export const SecurityEvent=mongoose.model('SecurityEvent',eventSchema);


