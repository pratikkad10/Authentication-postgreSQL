
import express from 'express';
import { forgotPassword, getUser, login, logout, register, resetPassword, verify } from '../controller/user.controller';
import { isLoggedIn } from '../middlewares/user.middleware';
const router= express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/logout',isLoggedIn, logout);
router.post('/verify', verify);
router.post('/forgot',isLoggedIn, forgotPassword);
router.post('/reset/:token',isLoggedIn, resetPassword);
router.get('/me', isLoggedIn, getUser);

export default router;