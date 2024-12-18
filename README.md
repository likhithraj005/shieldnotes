# Secure Notes Application

A secure notes web application with features like user management, role-based access, multi-factor authentication, and more. The application is built using Spring Boot for the backend, React for the frontend, and MySQL for the database. Security measures such as CSRF protection, JWT authentication, OAuth2 integration, and password management are implemented to ensure safe usage.

## Features

- **User Management**: Admin page to manage user credentials.
- **Role-Based Authorization**: Implemented role-based access control (RBAC) to assign specific roles to users for secure access.
- **Password Security & Management**: Includes features like Forgot Password for easy account recovery and secure password storage.
- **Multi-Factor Authentication**: Adds an extra layer of security by requiring multiple forms of verification during login.
- **CSRF Protection**: Cross-Site Request Forgery (CSRF) protection to prevent malicious attacks on the user.
- **JWT Authentication**: Used JSON Web Tokens (JWT) for secure user authentication.
- **OAuth2 Integration**: Supports third-party authentication via Google and GitHub for a seamless login experience.

## Technologies Used

- **Backend**: Spring Boot
- **Frontend**: React
- **Database**: MySQL (Hosted on Aiven)
- **Authentication**: JWT, OAuth2
- **Security**: CSRF Protection, Multi-Factor Authentication
- **Containerization**: Docker (for building and deploying the application)

## Deployment

- **Backend (Spring Boot)**: Deployed on Render: https://note-deployment-latest.onrender.com
- **Frontend (React)**: Deployed on Netlify: https://shieldnotes.netlify.app
- **Database (MySQL)**: Hosted on Aiven Console

## API Testing
You can test the API endpoints using Postman: https://documenter.getpostman.com/view/29635048/2sAYJ1kMuA
