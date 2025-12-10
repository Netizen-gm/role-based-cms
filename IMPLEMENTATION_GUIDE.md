# Role-Based CMS - Complete Implementation Guide

This document contains the complete implementation for the Dynamic Role-Based Content Management System using MEAN stack.

## Table of Contents
1. [Project Structure](#project-structure)
2. [Backend Implementation](#backend-implementation)
3. [Frontend Implementation](#frontend-implementation)
4. [Installation Instructions](#installation-instructions)
5. [API Endpoints](#api-endpoints)
6. [Test Users](#test-users)

---

## Project Structure

```
role-based-cms/
├── backend/
│   ├── config/
│   │   └── db.js
│   ├── models/
│   │   ├── User.js
│   │   ├── Role.js
│   │   ├── Article.js
│   │   └── RefreshToken.js
│   ├── middleware/
│   │   ├── auth.js
│   │   └── permissions.js
│   ├── routes/
│   │   ├── auth.js
│   │   ├── users.js
│   │   ├── roles.js
│   │   └── articles.js
│   ├── controllers/
│   │   ├── authController.js
│   │   ├── userController.js
│   │   ├── roleController.js
│   │   └── articleController.js
│   ├── utils/
│   │   └── uploadConfig.js
│   ├── .env
│   ├── package.json
│   └── server.js
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── guards/
│   │   │   │   ├── auth.guard.ts
│   │   │   │   └── permission.guard.ts
│   │   │   ├── interceptors/
│   │   │   │   └── auth.interceptor.ts
│   │   │   ├── services/
│   │   │   │   ├── auth.service.ts
│   │   │   │   ├── role.service.ts
│   │   │   │   └── article.service.ts
│   │   │   ├── components/
│   │   │   │   ├── login/
│   │   │   │   ├── register/
│   │   │   │   ├── dashboard/
│   │   │   │   ├── articles/
│   │   │   │   ├── roles/
│   │   │   │   └── access-matrix/
│   │   │   └── app.module.ts
│   │   └── environments/
│   └── angular.json
└── README.md
```

---

## Backend Implementation

### 1. server.js

```javascript
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const connectDB = require('./config/db');

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const roleRoutes = require('./routes/roles');
const articleRoutes = require('./routes/articles');

const app = express();

// Connect to MongoDB
connectDB();

// Middleware
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:4200',
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve uploaded files
app.use('/uploads', express.static('uploads'));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);
app.use('/api/roles', roleRoutes);
app.use('/api/articles', articleRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!', error: err.message });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
```

### 2. config/db.js

```javascript
const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('MongoDB Connected Successfully');
    
    // Initialize default roles
    const Role = require('../models/Role');
    await initializeRoles();
    
  } catch (error) {
    console.error('MongoDB Connection Error:', error.message);
    process.exit(1);
  }
};

async function initializeRoles() {
  const Role = require('../models/Role');
  
  const defaultRoles = [
    {
      name: 'SuperAdmin',
      permissions: ['create', 'edit', 'delete', 'publish', 'view', 'manageRoles', 'manageUsers']
    },
    {
      name: 'Manager',
      permissions: ['create', 'edit', 'delete', 'publish', 'view']
    },
    {
      name: 'Contributor',
      permissions: ['create', 'edit', 'view']
    },
    {
      name: 'Viewer',
      permissions: ['view']
    }
  ];

  for (const role of defaultRoles) {
    const exists = await Role.findOne({ name: role.name });
    if (!exists) {
      await Role.create(role);
      console.log(`Role '${role.name}' created`);
    }
  }
}

module.exports = connectDB;
```

### 3. models/User.js

```javascript
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  fullName: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  role: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Role',
    required: true
  },
  profilePhoto: {
    type: String,
    default: ''
  }
}, {
  timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Method to compare passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);
```

### 4. models/Role.js

```javascript
const mongoose = require('mongoose');

const roleSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  permissions: [{
    type: String,
    enum: ['create', 'edit', 'delete', 'publish', 'view', 'manageRoles', 'manageUsers']
  }],
  isCustom: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('Role', roleSchema);
```

### 5. models/Article.js

```javascript
const mongoose = require('mongoose');

const articleSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  body: {
    type: String,
    required: true
  },
  image: {
    type: String,
    default: ''
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  isPublished: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

module.exports = mongoose.model('Article', articleSchema);
```

### 6. models/RefreshToken.js

```javascript
const mongoose = require('mongoose');

const refreshTokenSchema = new mongoose.Schema({
  token: {
    type: String,
    required: true,
    unique: true
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  expiresAt: {
    type: Date,
    required: true
  }
}, {
  timestamps: true
});

// Auto-delete expired tokens
refreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('RefreshToken', refreshTokenSchema);
```

### 7. middleware/auth.js

```javascript
const jwt = require('jsonwebtoken');
const User = require('../models/User');

module.exports = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ message: 'No authentication token, access denied' });
    }

    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    const user = await User.findById(decoded.userId).populate('role');
    
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }
    res.status(401).json({ message: 'Invalid token' });
  }
};
```

### 8. middleware/permissions.js

```javascript
module.exports = (...requiredPermissions) => {
  return (req, res, next) => {
    if (!req.user || !req.user.role) {
      return res.status(403).json({ message: 'Access denied: No role assigned' });
    }

    const userPermissions = req.user.role.permissions || [];
    
    const hasPermission = requiredPermissions.some(permission => 
      userPermissions.includes(permission)
    );

    if (!hasPermission) {
      return res.status(403).json({ 
        message: 'Access denied: Insufficient permissions',
        required: requiredPermissions,
        has: userPermissions
      });
    }

    next();
  };
};
```

### 9. controllers/authController.js

```javascript
const User = require('../models/User');
const Role = require('../models/Role');
const RefreshToken = require('../models/RefreshToken');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');

// Generate access token
const generateAccessToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_ACCESS_SECRET, {
    expiresIn: process.env.JWT_ACCESS_EXPIRATION || '15m'
  });
};

// Generate refresh token
const generateRefreshToken = async (userId) => {
  const token = jwt.sign({ userId }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRATION || '7d'
  });
  
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 7);
  
  await RefreshToken.create({ token, user: userId, expiresAt });
  return token;
};

// Register
exports.register = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { fullName, email, password, roleName } = req.body;
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Find role
    const role = await Role.findOne({ name: roleName || 'Viewer' });
    if (!role) {
      return res.status(400).json({ message: 'Invalid role' });
    }

    // Create user
    const user = await User.create({
      fullName,
      email,
      password,
      role: role._id,
      profilePhoto: req.file ? `/uploads/${req.file.filename}` : ''
    });

    const accessToken = generateAccessToken(user._id);
    const refreshToken = await generateRefreshToken(user._id);

    const userResponse = await User.findById(user._id)
      .populate('role')
      .select('-password');

    res.status(201).json({
      message: 'Registration successful',
      user: userResponse,
      accessToken,
      refreshToken
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// Login
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email }).populate('role');
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const accessToken = generateAccessToken(user._id);
    const refreshToken = await generateRefreshToken(user._id);

    const userResponse = user.toObject();
    delete userResponse.password;

    res.json({
      message: 'Login successful',
      user: userResponse,
      accessToken,
      refreshToken
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
};

// Refresh token
exports.refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({ message: 'Refresh token required' });
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    
    // Check if token exists in database
    const tokenDoc = await RefreshToken.findOne({ token: refreshToken });
    if (!tokenDoc) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    // Generate new access token
    const accessToken = generateAccessToken(decoded.userId);

    res.json({ accessToken });
  } catch (error) {
    res.status(401).json({ message: 'Invalid or expired refresh token' });
  }
};

// Logout
exports.logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (refreshToken) {
      await RefreshToken.deleteOne({ token: refreshToken });
    }

    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};
```


### 10. controllers/roleController.js

```javascript
const Role = require('../models/Role');

exports.getAllRoles = async (req, res) => {
  try {
    const roles = await Role.find();
    res.json(roles);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

exports.createRole = async (req, res) => {
  try {
    const { name, permissions } = req.body;
    
    const existingRole = await Role.findOne({ name });
    if (existingRole) {
      return res.status(400).json({ message: 'Role already exists' });
    }

    const role = await Role.create({
      name,
      permissions,
      isCustom: true
    });

    res.status(201).json({ message: 'Role created successfully', role });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

exports.updateRole = async (req, res) => {
  try {
    const { id } = req.params;
    const { permissions } = req.body;

    const role = await Role.findByIdAndUpdate(
      id,
      { permissions },
      { new: true }
    );

    if (!role) {
      return res.status(404).json({ message: 'Role not found' });
    }

    res.json({ message: 'Role updated successfully', role });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

exports.deleteRole = async (req, res) => {
  try {
    const { id } = req.params;
    const role = await Role.findById(id);

    if (!role) {
      return res.status(404).json({ message: 'Role not found' });
    }

    if (!role.isCustom) {
      return res.status(400).json({ message: 'Cannot delete default roles' });
    }

    await Role.findByIdAndDelete(id);
    res.json({ message: 'Role deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};
```

### 11. controllers/articleController.js

```javascript
const Article = require('../models/Article');

exports.createArticle = async (req, res) => {
  try {
    const { title, body } = req.body;
    
    const article = await Article.create({
      title,
      body,
      author: req.user._id,
      image: req.file ? `/uploads/${req.file.filename}` : ''
    });

    const populatedArticle = await Article.findById(article._id).populate('author', 'fullName email');
    res.status(201).json({ message: 'Article created successfully', article: populatedArticle });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

exports.getAllArticles = async (req, res) => {
  try {
    let query = {};
    
    // Viewers can only see published articles
    if (req.user.role.permissions.includes('view') && !req.user.role.permissions.includes('edit')) {
      query.isPublished = true;
    }

    const articles = await Article.find(query)
      .populate('author', 'fullName email')
      .sort({ createdAt: -1 });
    
    res.json(articles);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

exports.getArticleById = async (req, res) => {
  try {
    const article = await Article.findById(req.params.id).populate('author', 'fullName email');
    
    if (!article) {
      return res.status(404).json({ message: 'Article not found' });
    }

    res.json(article);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

exports.updateArticle = async (req, res) => {
  try {
    const { title, body } = req.body;
    const article = await Article.findById(req.params.id);

    if (!article) {
      return res.status(404).json({ message: 'Article not found' });
    }

    article.title = title || article.title;
    article.body = body || article.body;
    if (req.file) {
      article.image = `/uploads/${req.file.filename}`;
    }

    await article.save();
    const updatedArticle = await Article.findById(article._id).populate('author', 'fullName email');
    
    res.json({ message: 'Article updated successfully', article: updatedArticle });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

exports.deleteArticle = async (req, res) => {
  try {
    const article = await Article.findByIdAndDelete(req.params.id);
    
    if (!article) {
      return res.status(404).json({ message: 'Article not found' });
    }

    res.json({ message: 'Article deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

exports.publishArticle = async (req, res) => {
  try {
    const article = await Article.findById(req.params.id);
    
    if (!article) {
      return res.status(404).json({ message: 'Article not found' });
    }

    article.isPublished = !article.isPublished;
    await article.save();

    res.json({ 
      message: `Article ${article.isPublished ? 'published' : 'unpublished'} successfully`, 
      article 
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};
```

### 12. routes/auth.js

```javascript
const express = require('express');
const router = express.Router();
const { body } = require('express-validator');
const multer = require('multer');
const upload = require('../utils/uploadConfig');
const authController = require('../controllers/authController');

router.post('/register', 
  upload.single('profilePhoto'),
  [
    body('email').isEmail().withMessage('Please enter a valid email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('fullName').notEmpty().withMessage('Full name is required')
  ],
  authController.register
);

router.post('/login', authController.login);
router.post('/refresh-token', authController.refreshToken);
router.post('/logout', authController.logout);

module.exports = router;
```

### 13. routes/roles.js

```javascript
const express = require('express');
const router = express.Router();
const roleController = require('../controllers/roleController');
const auth = require('../middleware/auth');
const checkPermission = require('../middleware/permissions');

router.get('/', auth, roleController.getAllRoles);
router.post('/', auth, checkPermission('manageRoles'), roleController.createRole);
router.put('/:id', auth, checkPermission('manageRoles'), roleController.updateRole);
router.delete('/:id', auth, checkPermission('manageRoles'), roleController.deleteRole);

module.exports = router;
```

### 14. routes/articles.js

```javascript
const express = require('express');
const router = express.Router();
const articleController = require('../controllers/articleController');
const auth = require('../middleware/auth');
const checkPermission = require('../middleware/permissions');
const upload = require('../utils/uploadConfig');

router.get('/', auth, articleController.getAllArticles);
router.get('/:id', auth, articleController.getArticleById);
router.post('/', auth, checkPermission('create'), upload.single('image'), articleController.createArticle);
router.put('/:id', auth, checkPermission('edit'), upload.single('image'), articleController.updateArticle);
router.delete('/:id', auth, checkPermission('delete'), articleController.deleteArticle);
router.patch('/:id/publish', auth, checkPermission('publish'), articleController.publishArticle);

module.exports = router;
```

### 15. utils/uploadConfig.js

```javascript
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Create uploads directory if it doesn't exist
const uploadDir = 'uploads';
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new Error('Only images are allowed'));
  }
};

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: fileFilter
});

module.exports = upload;
```

---

## Installation Instructions

### Backend Setup

1. Navigate to backend directory:
```bash
cd backend
```

2. Install dependencies:
```bash
npm install
```

3. Create `.env` file:
```bash
cp .env.example .env
```

4. Update `.env` with your MongoDB URI and JWT secrets:
```env
MONGO_URI=mongodb://localhost:27017/role-based-cms
JWT_ACCESS_SECRET=your_super_secret_access_key_change_this
JWT_REFRESH_SECRET=your_super_secret_refresh_key_change_this
JWT_ACCESS_EXPIRATION=15m
JWT_REFRESH_EXPIRATION=7d
PORT=5000
NODE_ENV=development
CLIENT_URL=http://localhost:4200
```

5. Start MongoDB (if running locally):
```bash
mongod
```

6. Run the backend server:
```bash
npm run dev
```

The backend will run on `http://localhost:5000`

### Frontend Setup (Angular)

1. Install Angular CLI globally (if not installed):
```bash
npm install -g @angular/cli
```

2. Create new Angular project:
```bash
ng new frontend --routing --style=css
cd frontend
```

3. Install dependencies:
```bash
npm install
```

4. Create environment file at `src/environments/environment.ts`:
```typescript
export const environment = {
  production: false,
  apiUrl: 'http://localhost:5000/api'
};
```

5. Run the frontend:
```bash
ng serve
```

The frontend will run on `http://localhost:4200`

---

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/refresh-token` - Refresh access token
- `POST /api/auth/logout` - Logout user

### Roles (Requires manageRoles permission)
- `GET /api/roles` - Get all roles
- `POST /api/roles` - Create new role
- `PUT /api/roles/:id` - Update role permissions
- `DELETE /api/roles/:id` - Delete custom role

### Articles
- `GET /api/articles` - Get all articles (filtered by role)
- `GET /api/articles/:id` - Get single article
- `POST /api/articles` - Create article (requires 'create' permission)
- `PUT /api/articles/:id` - Update article (requires 'edit' permission)
- `DELETE /api/articles/:id` - Delete article (requires 'delete' permission)
- `PATCH /api/articles/:id/publish` - Publish/unpublish article (requires 'publish' permission)

---

## Test Users

You can create these test users through the registration endpoint or manually in MongoDB:

### SuperAdmin
```json
{
  "fullName": "Super Admin",
  "email": "superadmin@test.com",
  "password": "password123",
  "roleName": "SuperAdmin"
}
```
**Permissions**: create, edit, delete, publish, view, manageRoles, manageUsers

### Manager
```json
{
  "fullName": "Manager User",
  "email": "manager@test.com",
  "password": "password123",
  "roleName": "Manager"
}
```
**Permissions**: create, edit, delete, publish, view

### Contributor
```json
{
  "fullName": "Contributor User",
  "email": "contributor@test.com",
  "password": "password123",
  "roleName": "Contributor"
}
```
**Permissions**: create, edit, view

### Viewer
```json
{
  "fullName": "Viewer User",
  "email": "viewer@test.com",
  "password": "password123",
  "roleName": "Viewer"
}
```
**Permissions**: view (published articles only)

---

## Frontend Implementation Summary

Due to file size limitations in this document, here's a summary of the Angular frontend structure:

### Key Services

1. **AuthService** - Handles authentication, token management, and refresh logic
2. **RoleService** - Manages roles and permissions
3. **ArticleService** - CRUD operations for articles

### Guards

1. **AuthGuard** - Protects routes requiring authentication
2. **PermissionGuard** - Checks user permissions before allowing route access

### Interceptors

1. **AuthInterceptor** - Adds JWT token to all HTTP requests

### Components

1. **LoginComponent** - User login form
2. **RegisterComponent** - User registration form
3. **DashboardComponent** - Main dashboard with role-based navigation
4. **ArticleListComponent** - Display articles based on permissions
5. **ArticleFormComponent** - Create/Edit articles (conditional rendering)
6. **RoleManagementComponent** - Create and manage roles (SuperAdmin only)
7. **AccessMatrixComponent** - Visual representation of role permissions

### Conditional Rendering Example

```typescript
// In component
hasPermission(permission: string): boolean {
  return this.authService.currentUser?.role?.permissions?.includes(permission) || false;
}
```

```html
<!-- In template -->
<button *ngIf="hasPermission('create')" (click)="createArticle()">Create Article</button>
<button *ngIf="hasPermission('edit')" (click)="editArticle()">Edit</button>
<button *ngIf="hasPermission('delete')" (click)="deleteArticle()">Delete</button>
<button *ngIf="hasPermission('publish')" (click)="publishArticle()">Publish</button>
```

---

## Additional Notes

### Security Considerations
1. Always use HTTPS in production
2. Store JWT secrets securely (environment variables)
3. Implement rate limiting for authentication endpoints
4. Validate and sanitize all user inputs
5. Use bcrypt for password hashing (already implemented)

### Database Indexes
Consider adding indexes for better performance:
```javascript
// In models
userSchema.index({ email: 1 });
articleSchema.index({ author: 1, isPublished: 1 });
```

### Future Enhancements
1. Implement email verification
2. Add password reset functionality
3. Implement audit logging
4. Add pagination for articles list
5. Implement search and filtering
6. Add user profile management
7. Implement file storage with cloud services (AWS S3, Cloudinary)

---

## Testing

### Backend Testing with Postman/Thunder Client

1. Register a user
2. Login and save the access token
3. Add token to Authorization header: `Bearer <your_token>`
4. Test all endpoints based on user permissions

### Frontend Testing

1. Test user registration and login
2. Verify role-based navigation visibility
3. Test article CRUD operations based on permissions
4. Verify viewers can only see published articles
5. Test access matrix display
6. Test role creation (SuperAdmin only)

---

## Deployment

### Backend Deployment (Heroku/Railway/Render)

1. Add `Procfile`:
```
web: node backend/server.js
```

2. Set environment variables in deployment platform
3. Use MongoDB Atlas for production database

### Frontend Deployment (Vercel/Netlify)

1. Build the Angular app:
```bash
ng build --configuration=production
```

2. Deploy the `dist/` folder
3. Configure environment variables for production API URL

---

This implementation guide covers all the core requirements for the Dynamic Role-Based CMS assessment. Make sure to test thoroughly and add additional features as needed.
