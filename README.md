# Assignment Planner

A web application to help students manage assignments, visualise workload, and track progress.

**Group 38** — Building Useable Software (BUS)  
**Challenge 3:** Student Help Platform

🔗 **Live Demo:** https://bus38-project-production.up.railway.app/login

## Team

| Student ID | Name | Role | Stories |
|------------|------|------|---------|
| 2615836 | Muhammad Kalang | Personas, Stories, Tests, Diagrams, Code | S3, S4, S5 |
| 3066929 | Emmanuel Onyenyili | Diagrams, Analytics | S7, S8 |
| 3065706 | Sri Mandava | Coding, Deployment | S1, S2, S6 |

## Features

### Feature 1: Assignment Management (S1-S4)
| Story | Description |
|-------|-------------|
| S1 | Add assignments with name, module, and deadline |
| S2 | View all saved assignments in a list |
| S3 | Mark assignments as complete |
| S4 | Edit assignment details |

### Feature 2: Priority & Calendar (S5-S6)
| Story | Description |
|-------|-------------|
| S5 | Assignments due within 5 days highlighted as high priority |
| S6 | Monthly calendar view showing assignments on due dates |

### Feature 3: Analytics Dashboard (S7-S8)
| Story | Description |
|-------|-------------|
| S7 | Stats overview: total, completed, pending counts |
| S8 | Workload breakdown by module |

## Tech Stack

- **Backend:** Python 3, Flask
- **Database:** SQLite, SQLAlchemy
- **Authentication:** Flask-Login
- **Frontend:** HTML, Jinja2, Bootstrap 5
- **Deployment:** Railway

## Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/sathvik2612/bus38-project.git
cd bus38-project
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the application
```bash
python app.py
```

### 4. Open in browser
```
http://localhost:5000
```

## Project Structure

```
bus38-project/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── workload.db           # SQLite database (auto-created)
├── templates/
│   ├── base.html         # Base layout with navbar
│   ├── login.html        # Login page
│   ├── register.html     # Registration page
│   ├── index.html        # Assignment list (S2)
│   ├── add.html          # Add assignment form (S1)
│   ├── edit.html         # Edit assignment form (S4)
│   ├── calendar.html     # Calendar view (S6)
│   └── analytics.html    # Analytics dashboard (S7, S8)
└── README.md
```

## Personas

### Joshua (Student)
- **Goals:** Start assignments early, avoid last-minute stress, have more free time
- **Pain Points:** Assignments scattered across Canvas, notes, emails. Deadlines often forgotten.
- **Stories:** S1-S8

### Jane (Student)
- **Goals:** View all assignments at once, allocate time properly
- **Pain Points:** Hard to decide what to prioritise. Doesn't know if on track.
- **Stories:** S5-S8

## Sprint Summary

| Sprint | Planned | Delivered | Not Completed |
|--------|---------|-----------|---------------|
| Sprint 1 (Weeks 2-6) | S1, S2, S3, S4 | S1, S2 | S3, S4 |
| Sprint 2 (Weeks 7-11) | S5, S6, S7, S8 | S3, S4, S5, S6, S7, S8 | None |

## Deployment

🔗 **Live Demo:** https://bus38-project-production.up.railway.app/login


Deployed on Railway platform (https://railway.app)

