
import express from 'express';
import { forgotPassword, getUser, login, logout, register, resetPassword, verify } from '../controller/user.controller.js';
import { isLoggedIn } from '../middlewares/user.middleware.js';
const router= express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/logout',isLoggedIn, logout);
router.get('/verify/:token', verify);
router.post('/forgot',isLoggedIn, forgotPassword);
router.post('/reset/:token',isLoggedIn, resetPassword);
router.get('/me', isLoggedIn, getUser);

export default router;