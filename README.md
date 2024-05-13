# School Module Backend

This project implements a backend system for a school module with role-based access control, allowing different actions to be performed by superusers, principals, teachers, and students.

## Features

- User authentication and authorization.
- CRUD operations on users.
- Role-based access control for different user types.
- Secure password storage with bcrypt.
- Image upload capabilities for user profiles.

## Technologies

- Node.js
- Express
- MySQL
- JWT for authentication
- bcrypt.js for password hashing
- multer for handling file uploads

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

- Node.js
- MySQL

Installing

Clone the repository:
git clone https://github.com/sachidhaturaha/School_Module.git

Navigate into the project directory:
cd school

Install the required packages:
npm install

Set up your MySQL database by running the SQL scripts located in the sql_scripts file.

Running the server
To start the server, run:
node start or nodemon start

The server should now be running on http://localhost:8081.