# SkillConnect

A platform that connects learners with tutors in any skill area. Currently India-only (prices in INR).

## Run it
1. Install Node.js 18 or newer (https://nodejs.org).
2. In this folder run:  `node server.js`
3. Open http://localhost:3000

No `npm install` is needed. The backend uses only built-in Node modules.

## Demo accounts
| Role    | Email                     | Password     |
|---------|---------------------------|--------------|
| Learner | learner@skillconnect.in   | Learner@123  |
| Tutor   | tutor@skillconnect.in     | Tutor@123    |

Try it: log in as the learner, request a session with "Arjun Mehta", log out,
then log in as the tutor and accept or decline it on the dashboard.

## Structure
- `server.js`        backend (API + serves the website)
- `data/db.json`     database file (users, tutors, bookings)
- `public/`          index.html (home), login.html, dashboard.html, auth.css

## API
| Method | Path               | Who       | Purpose              |
|--------|--------------------|-----------|----------------------|
| GET    | /api/tutors        | anyone    | list tutors          |
| POST   | /api/register      | anyone    | create account       |
| POST   | /api/login         | anyone    | log in (sets cookie) |
| POST   | /api/logout        | anyone    | log out              |
| GET    | /api/me            | logged in | current user         |
| GET    | /api/bookings      | logged in | your bookings        |
| POST   | /api/bookings      | learner   | request a session    |
| PATCH  | /api/bookings/:id  | tutor     | accept or decline    |

## Security already included
Passwords hashed with scrypt + salt, signed HttpOnly session cookie, role checks
on every route, login rate limiting, request size limit, path-traversal protection.

## Next steps for the 4th-year project
Move from db.json to PostgreSQL or MongoDB, tutor profile editing and verification,
availability calendar, Razorpay (UPI) payments, video classes, reviews, admin panel,
HTTPS and deployment.
