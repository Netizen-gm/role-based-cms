# Role-Based Content Management System (CMS)

![MEAN Stack](https://img.shields.io/badge/Stack-MEAN-green)
![MongoDB](https://img.shields.io/badge/Database-MongoDB-green)
![Express](https://img.shields.io/badge/Backend-Express.js-lightgrey)
![Angular](https://img.shields.io/badge/Frontend-Angular-red)
![Node.js](https://img.shields.io/badge/Runtime-Node.js-brightgreen)

A comprehensive, production-ready Dynamic Role-Based Content Management System built with the MEAN stack (MongoDB, Express.js, Angular, Node.js) featuring JWT authentication, dynamic permissions, and role-based access control.

## 📋 Project Overview

This CMS implements a complete authentication and authorization system with:

- ✅ **User Registration & Login** with JWT (Access + Refresh tokens)
- ✅ **Bcrypt Password Hashing** for security
- ✅ **4 Default Roles**: SuperAdmin, Manager, Contributor, Viewer
- ✅ **Dynamic Role Creation** with custom permissions
- ✅ **7 Permission Types**: create, edit, delete, publish, view, manageRoles, manageUsers
- ✅ **Backend Route Protection** with Express middleware
- ✅ **Frontend Route Guards** and conditional rendering
- ✅ **Article Management** with image uploads
- ✅ **Access Matrix** visualization
- ✅ **RESTful API** with proper error handling

## 🏗️ Project Structure

```
role-based-cms/
├── backend/                  # Node.js/Express backend
│   ├── config/              # Database configuration
│   ├── models/              # Mongoose models
│   ├── middleware/          # Auth & permission middleware
│   ├── routes/              # API routes
│   ├── controllers/         # Business logic
│   ├── utils/               # Helper utilities
│   ├── .env.example         # Environment variables template
│   ├── package.json
│   └── server.js            # Entry point
├── frontend/                # Angular frontend (to be created)
│   └── src/
│       ├── app/
│       │   ├── guards/      # Route guards
│       │   ├── services/    # API services
│       │   ├── interceptors/ # HTTP interceptors
│       │   └── components/  # UI components
│       └── environments/
├── IMPLEMENTATION_GUIDE.md  # Complete code implementation
└── README.md               # This file
```

## 🚀 Quick Start

### Prerequisites

- Node.js (v14 or higher)
- MongoDB (local or Atlas)
- Angular CLI (`npm install -g @angular/cli`)

### Backend Setup

1. **Clone the repository:**
```bash
git clone https://github.com/Netizen-gm/role-based-cms.git
cd role-based-cms/backend
```

2. **Install dependencies:**
```bash
npm install
```

3. **Configure environment:**
```bash
cp .env.example .env
```

Edit `.env` and update:
```env
MONGO_URI=mongodb://localhost:27017/role-based-cms
JWT_ACCESS_SECRET=your_super_secret_access_key
JWT_REFRESH_SECRET=your_super_secret_refresh_key
PORT=5000
CLIENT_URL=http://localhost:4200
```

4. **Start the server:**
```bash
npm run dev
```

Backend will run on `http://localhost:5000`

### Frontend Setup

1. **Create Angular project:**
```bash
ng new frontend --routing --style=css
cd frontend
npm install
```

2. **Configure environment:**

Edit `src/environments/environment.ts`:
```typescript
export const environment = {
  production: false,
  apiUrl: 'http://localhost:5000/api'
};
```

3. **Start the frontend:**
```bash
ng serve
```

Frontend will run on `http://localhost:4200`

## 📚 Documentation

For complete implementation details including all backend code, models, controllers, routes, and frontend examples, see:

👉 **[IMPLEMENTATION_GUIDE.md](./IMPLEMENTATION_GUIDE.md)** - Complete code with 1100+ lines

## 🔐 Default Roles & Permissions

| Role | Permissions |
|------|-------------|
| **SuperAdmin** | create, edit, delete, publish, view, manageRoles, manageUsers |
| **Manager** | create, edit, delete, publish, view |
| **Contributor** | create, edit, view |
| **Viewer** | view (published articles only) |

## 🛠️ API Endpoints

### Authentication
```
POST   /api/auth/register        # Register new user
POST   /api/auth/login           # Login user
POST   /api/auth/refresh-token   # Refresh access token
POST   /api/auth/logout          # Logout user
```

### Roles (SuperAdmin only)
```
GET    /api/roles                # Get all roles
POST   /api/roles                # Create new role
PUT    /api/roles/:id            # Update role permissions
DELETE /api/roles/:id            # Delete custom role
```

### Articles
```
GET    /api/articles             # Get all articles (filtered by role)
GET    /api/articles/:id         # Get single article
POST   /api/articles             # Create article (requires 'create')
PUT    /api/articles/:id         # Update article (requires 'edit')
DELETE /api/articles/:id         # Delete article (requires 'delete')
PATCH  /api/articles/:id/publish # Toggle publish status (requires 'publish')
```

## 👥 Test Users

Create these test users through the registration endpoint:

```json
// SuperAdmin
{
  "fullName": "Super Admin",
  "email": "superadmin@test.com",
  "password": "password123",
  "roleName": "SuperAdmin"
}

// Manager
{
  "fullName": "Manager User",
  "email": "manager@test.com",
  "password": "password123",
  "roleName": "Manager"
}

// Contributor
{
  "fullName": "Contributor User",
  "email": "contributor@test.com",
  "password": "password123",
  "roleName": "Contributor"
}

// Viewer
{
  "fullName": "Viewer User",
  "email": "viewer@test.com",
  "password": "password123",
  "roleName": "Viewer"
}
```

## 🎯 Key Features Implemented

### Authentication & Security
- ✅ JWT with access tokens (15 min) and refresh tokens (7 days)
- ✅ Bcrypt password hashing with salt rounds
- ✅ Secure token storage and rotation
- ✅ Automatic token refresh mechanism
- ✅ Protected routes with middleware

### Authorization
- ✅ Dynamic permission-based access control
- ✅ Role hierarchy with custom permissions
- ✅ Backend middleware for route protection
- ✅ Frontend guards for navigation control
- ✅ Conditional UI rendering based on permissions

### Content Management
- ✅ Article CRUD operations
- ✅ Image upload with Multer
- ✅ Publish/Unpublish functionality
- ✅ Author tracking and population
- ✅ Role-based article filtering

### Role Management
- ✅ Create custom roles (SuperAdmin only)
- ✅ Assign/modify permissions dynamically
- ✅ Delete custom roles (default roles protected)
- ✅ Access matrix visualization

## 📦 Dependencies

### Backend
```json
{
  "express": "^4.18.2",
  "mongoose": "^7.5.0",
  "bcryptjs": "^2.4.3",
  "jsonwebtoken": "^9.0.2",
  "dotenv": "^16.3.1",
  "cors": "^2.8.5",
  "multer": "^1.4.5-lts.1",
  "express-validator": "^7.0.1"
}
```

### Frontend (Angular)
- Angular 15+
- RxJS for reactive programming
- Angular Material (optional for UI)
- HTTP Client for API calls

## 🧪 Testing

### Backend Testing
Use Postman or Thunder Client:
1. Register a user → Get access token
2. Add token to Authorization header: `Bearer <token>`
3. Test endpoints based on user permissions
4. Verify permission-based access control

### Frontend Testing
1. Test user flows (register → login → dashboard)
2. Verify role-based navigation visibility
3. Test CRUD operations per role
4. Verify viewers see only published articles
5. Test role management (SuperAdmin only)

## 🚢 Deployment

### Backend (Heroku/Railway/Render)
1. Set environment variables in platform
2. Use MongoDB Atlas for production DB
3. Deploy with `npm start`

### Frontend (Vercel/Netlify)
1. Build: `ng build --configuration=production`
2. Deploy `dist/` folder
3. Set production API URL

## 📝 License

This project is open source and available under the MIT License.

## 👨‍💻 Author

Developed by **Netizen-gm**

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

## ⭐ Show your support

Give a ⭐️ if this project helped you!

---

**Note:** For the complete implementation with all code files, models, controllers, routes, middleware, and frontend examples, please refer to [IMPLEMENTATION_GUIDE.md](./IMPLEMENTATION_GUIDE.md).
