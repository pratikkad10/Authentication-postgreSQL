const { PrismaClient } = require('@prisma/client');
const { sendMail } = require('../utils/sendMail');
const prisma = new PrismaClient();


const register = async (req, res) => {
    const {name, email, password, role} = req.body;

    try {
        if(!name || !email || !password || !role) {
            return res.status(400).json({message: "All fields are required"});
        }

        const existingUser = await prisma.user.findUnique({
            where: {
                email: email
            }
        });

        if(existingUser) {     
            return res.status(400).json({message: "User already exists"});
        } 

        const hashedPassword = await bcrypt.hash(password, 10);
        if(!hashedPassword) {
            return res.status(500).json({message: "Error hashing password"});
        }

        const user = await prisma.user.create({
            data: {
                name,
                email,
                password:hashedPassword,
                role
            }
        });

        const token = crypto.randomBytes(32).toString("hex");
        
        const updatedUser = await prisma.user.update({
            where: { id: user.id },
            data: { verificationToken: token }
        });

        await sendMail(user.email, "Verify your email", "Click the link to verify your email", `<a href="http://localhost:3000/api/v1/verify/${token}">Verify Email</a>`);

        return res.status(201).json({message: "User created successfully", user});
    } catch (error) {
        console.error(error);
        return res.status(500).json({message: "Internal server error"});
    }
}

const verify = async (req, res) => {
    const { token } = req.params;
    try {
        if(!token) {
            return res.status(400).json({message: "Token is required"});
        }

        const user = await prisma.user.findUnique({
            where: {
                verificationToken: token
            }
        });

        if(!user) {
            return res.status(400).json({message: "Invalid token"});
        }

        const updatedUser = await prisma.user.update({
            where: { id: user.id },
            data: { verificationToken: undefined, isVerified: true }
        });

        return res.status(200).json({message: "User verified successfully", user: updatedUser});

    } catch (error) {
        console.log(error);
        return res.status(500).json({message: "Internal server error", error: error.message});
    }
}

const login= async (req, res) => {
    const {email, password} = req.body;
    try {
        if(!email || !password) {
            return res.status(400).json({message: "All fields are required"});
        }
        const user = await prisma.user.findUnique({
            where: {
                email: email
            }
        });
        if(!user) {
            return res.status(400).json({message: "User not found"});
        }
        const isMatch = await bcrypt.compare(password, user.password);     

        if(!isMatch) {
            return res.status(400).json({message: "Invalid credentials"});
        }

        if(!user.isVerified) {
            return res.status(400).json({message: "User not verified"});
        }

        const token = jwt.sign({id: user.id, role:user.role, email:user.email}, process.env.JWT_SECRET, {expiresIn: '1d'});

        const cookieOption= {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000, // 1 day
        };
        res.cookie("token", token, cookieOption);
        
        return res.status(200).json({
            message: "User logged in successfully",
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role,
                isVerified: user.isVerified
            },
            token: token
        })
    } catch (error) {
        return res.status(500).json({
            success:false,
            message:"Internal server error",
            error:error.message
        })
    }
}

const logout = async (req, res) => {
    try {
        res.clearCookie("token");
        return res.status(200).json({message: "User logged out successfully"});
    } catch (error) {
        return res.status(500).json({message: "Internal server error", error: error.message});
    }
}

const getUser = async (req, res) => {
    try {
        const user = await prisma.user.findUnique({
            where: {
                id: req.user.id
            }
        });
        if(!user) {
            return res.status(400).json({message: "User not found"});
        }
        return res.status(200).json({message: "User fetched successfully", user});
    } catch (error) {
        return res.status(500).json({message: "Internal server error", error: error.message});
    }
}

const forgotPassword = async (req, res) => {
    const { email } = req.body;
    try {
        if(!email) {
            return res.status(400).json({message: "Email is required"});
        }

        const user = await prisma.user.findUnique({
            where: {
                email: email
            }
        });

        if(!user) {
            return res.status(400).json({message: "User not found"});
        }

        const token = crypto.randomBytes(32).toString("hex");
        
        const updatedUser = await prisma.user.update({
            where: { id: user.id },
            data: { passwordResetToken: token, passwordResetTokenExpiry: new Date(Date.now() + 3600000) } // 1 hour expiry
        });

        await sendMail(user.email, "Reset your password", "Click the link to reset your password", `<a href="http://localhost:3000/api/v1/reset/${token}">Reset Password</a>`);

        return res.status(200).json({message: "Password reset link sent to email"});
        
    } catch (error) {
        return res.status(500).json({message: "Internal server error", error: error.message});
    }
}

const resetPassword = async (req, res) => {
    const token = req.params.token;
    const { password } = req.body;
    try {
        if(!token || !password) {
            return res.status(400).json({message: "Token and password are required"});
        }

        const user = await prisma.user.findUnique({
            where: {
                passwordResetToken: token,
                passwordResetTokenExpiry: {
                    gte: new Date(Date.now())
                }
            }
        });

        if(!user) {
            return res.status(400).json({message: "Invalid or expired token"});
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        
        const updatedUser = await prisma.user.update({
            where: { id: user.id },
            data: { password: hashedPassword, passwordResetToken: null, passwordResetTokenExpiry: null }
        });

        return res.status(200).json({message: "Password reset successfully", user: updatedUser});
        
    } catch (error) {
        return res.status(500).json({message: "Internal server error", error: error.message});
    }
}

export { register, verify, login, logout, getUser, forgotPassword, resetPassword };