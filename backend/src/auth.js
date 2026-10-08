import jwt from 'jsonwebtoken';
const secret=()=>process.env.JWT_SECRET || 'development-only-change-me';
export const tokenFor=(user)=>jwt.sign({id:user._id.toString(),username:user.username},secret(),{expiresIn:'8h'});
export const requireAuth=(req,res,next)=>{ try { req.user=jwt.verify((req.headers.authorization||'').replace('Bearer ',''),secret()); next(); } catch { res.status(401).json({error:'Authentication required'}); } };
