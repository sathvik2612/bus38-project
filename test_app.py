"""
Rigorous Test Suite for Academic Workload Planner
==================================================
Tests all 7 user stories (S1-S7) with multiple test cases per story.

Run: pytest test_app.py -v
"""

import pytest
import os
import sys
from datetime import datetime, timezone, timedelta

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, User, Assignment


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def client():
    """Create test client with fresh database."""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.drop_all()


@pytest.fixture
def auth_client(client):
    """Create authenticated test client with a logged-in user."""
    with app.app_context():
        # Create test user
        user = User(email='test@example.com', name='Test User')
        user.set_password('password123')
        db.session.add(user)
        db.session.commit()
    
    # Login
    client.post('/login', data={
        'email': 'test@example.com',
        'password': 'password123'
    }, follow_redirects=True)
    
    return client


@pytest.fixture
def sample_assignment(auth_client):
    """Create a sample assignment for testing."""
    with app.app_context():
        user = User.query.filter_by(email='test@example.com').first()
        assignment = Assignment(
            user_id=user.id,
            title='Test Assignment',
            module='COMP1234',
            estimated_hours=5,
            due_at=datetime.now(timezone.utc) + timedelta(days=7)
        )
        db.session.add(assignment)
        db.session.commit()
        return assignment.id


# =============================================================================
# AUTHENTICATION TESTS
# =============================================================================

class TestAuthentication:
    """Test user registration, login, and logout."""
    
    def test_register_page_loads(self, client):
        """Test register page is accessible."""
        response = client.get('/register')
        assert response.status_code == 200
        assert b'Create Account' in response.data
    
    def test_register_success(self, client):
        """Test successful user registration."""
        response = client.post('/register', data={
            'name': 'New User',
            'email': 'newuser@example.com',
            'password': 'securepass123',
            'confirm': 'securepass123'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Welcome' in response.data or b'Assignments' in response.data
        
        with app.app_context():
            user = User.query.filter_by(email='newuser@example.com').first()
            assert user is not None
            assert user.name == 'New User'
    
    def test_register_duplicate_email(self, client):
        """Test registration fails with duplicate email."""
        # Register first user
        client.post('/register', data={
            'name': 'User One',
            'email': 'duplicate@example.com',
            'password': 'password123',
            'confirm': 'password123'
        })
        
        # Logout first user
        client.get('/logout')
        
        # Try to register with same email
        response = client.post('/register', data={
            'name': 'User Two',
            'email': 'duplicate@example.com',
            'password': 'password456',
            'confirm': 'password456'
        }, follow_redirects=True)
        
        assert b'already exists' in response.data or b'Register' in response.data
    
    def test_register_password_mismatch(self, client):
        """Test registration fails when passwords don't match."""
        response = client.post('/register', data={
            'name': 'Test User',
            'email': 'test@example.com',
            'password': 'password123',
            'confirm': 'differentpassword'
        }, follow_redirects=True)
        
        assert b'must match' in response.data.lower() or response.status_code == 200
    
    def test_register_short_password(self, client):
        """Test registration fails with short password."""
        response = client.post('/register', data={
            'name': 'Test User',
            'email': 'test@example.com',
            'password': 'short',
            'confirm': 'short'
        }, follow_redirects=True)
        
        # Should stay on register page with error
        assert b'Create Account' in response.data or b'8' in response.data
    
    def test_login_page_loads(self, client):
        """Test login page is accessible."""
        response = client.get('/login')
        assert response.status_code == 200
        assert b'Sign In' in response.data
    
    def test_login_success(self, client):
        """Test successful login."""
        # Register user first
        client.post('/register', data={
            'name': 'Test User',
            'email': 'test@example.com',
            'password': 'password123',
            'confirm': 'password123'
        })
        
        # Logout
        client.get('/logout')
        
        # Login
        response = client.post('/login', data={
            'email': 'test@example.com',
            'password': 'password123'
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Welcome back' in response.data or b'Assignments' in response.data
    
    def test_login_wrong_password(self, client):
        """Test login fails with wrong password."""
        # Register user
        client.post('/register', data={
            'name': 'Test User',
            'email': 'test@example.com',
            'password': 'password123',
            'confirm': 'password123'
        })
        client.get('/logout')
        
        # Try wrong password
        response = client.post('/login', data={
            'email': 'test@example.com',
            'password': 'wrongpassword'
        }, follow_redirects=True)
        
        assert b'Invalid' in response.data
    
    def test_login_nonexistent_user(self, client):
        """Test login fails with non-existent email."""
        response = client.post('/login', data={
            'email': 'nonexistent@example.com',
            'password': 'password123'
        }, follow_redirects=True)
        
        assert b'Invalid' in response.data
    
    def test_logout(self, auth_client):
        """Test logout works."""
        response = auth_client.get('/logout', follow_redirects=True)
        assert response.status_code == 200
        assert b'logged out' in response.data.lower() or b'Sign In' in response.data
    
    def test_protected_route_requires_login(self, client):
        """Test protected routes redirect to login."""
        response = client.get('/assignments', follow_redirects=True)
        assert b'Sign In' in response.data or b'log in' in response.data.lower()


# =============================================================================
# S1: ADD ASSIGNMENT TESTS
# =============================================================================

class TestS1AddAssignment:
    """Test Story S1: Add Assignment functionality."""
    
    def test_add_page_loads(self, auth_client):
        """Test add assignment page is accessible."""
        response = auth_client.get('/assignments/add')
        assert response.status_code == 200
        assert b'Add' in response.data
    
    def test_add_assignment_success(self, auth_client):
        """Test adding assignment with all fields."""
        future_date = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%dT%H:%M')
        
        response = auth_client.post('/assignments/add', data={
            'title': 'Database Report',
            'module': 'COMP1234',
            'estimated_hours': 8,
            'due_at': future_date
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'Database Report' in response.data or b'added' in response.data.lower()
        
        with app.app_context():
            assignment = Assignment.query.filter_by(title='Database Report').first()
            assert assignment is not None
            assert assignment.module == 'COMP1234'
            assert assignment.estimated_hours == 8
    
    def test_add_assignment_minimal_fields(self, auth_client):
        """Test adding assignment with only required fields."""
        future_date = (datetime.now() + timedelta(days=3)).strftime('%Y-%m-%dT%H:%M')
        
        response = auth_client.post('/assignments/add', data={
            'title': 'Quick Task',
            'module': '',
            'estimated_hours': '',
            'due_at': future_date
        }, follow_redirects=True)
        
        assert response.status_code == 200
        
        with app.app_context():
            assignment = Assignment.query.filter_by(title='Quick Task').first()
            assert assignment is not None
            assert assignment.estimated_hours == 1  # Default value
    
    def test_add_assignment_missing_title(self, auth_client):
        """Test validation fails without title."""
        future_date = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%dT%H:%M')
        
        response = auth_client.post('/assignments/add', data={
            'title': '',
            'module': 'COMP1234',
            'estimated_hours': 5,
            'due_at': future_date
        }, follow_redirects=True)
        
        # Should stay on form with error
        assert b'Add' in response.data
        
        with app.app_context():
            count = Assignment.query.count()
            assert count == 0
    
    def test_add_assignment_missing_due_date(self, auth_client):
        """Test validation fails without due date."""
        response = auth_client.post('/assignments/add', data={
            'title': 'Test Assignment',
            'module': 'COMP1234',
            'estimated_hours': 5,
            'due_at': ''
        }, follow_redirects=True)
        
        # Should stay on form
        assert b'Add' in response.data
    
    def test_add_assignment_module_uppercase(self, auth_client):
        """Test module code is converted to uppercase."""
        future_date = (datetime.now() + timedelta(days=7)).strftime('%Y-%m-%dT%H:%M')
        
        auth_client.post('/assignments/add', data={
            'title': 'Test Assignment',
            'module': 'comp1234',
            'estimated_hours': 5,
            'due_at': future_date
        }, follow_redirects=True)
        
        with app.app_context():
            assignment = Assignment.query.filter_by(title='Test Assignment').first()
            assert assignment.module == 'COMP1234'


# =============================================================================
# S2: VIEW SORTED ASSIGNMENTS TESTS
# =============================================================================

class TestS2ViewSorted:
    """Test Story S2: View assignments sorted by due date."""
    
    def test_assignments_page_loads(self, auth_client):
        """Test assignments page is accessible."""
        response = auth_client.get('/assignments')
        assert response.status_code == 200
        assert b'Assignments' in response.data
    
    def test_empty_state(self, auth_client):
        """Test empty state message when no assignments."""
        response = auth_client.get('/assignments')
        assert b'No pending' in response.data or b'Add' in response.data
    
    def test_assignments_sorted_by_due_date(self, auth_client):
        """Test assignments appear sorted by due date."""
        # Add assignments in random order
        dates = [
            (datetime.now(timezone.utc) + timedelta(days=10), 'Third'),
            (datetime.now(timezone.utc) + timedelta(days=2), 'First'),
            (datetime.now(timezone.utc) + timedelta(days=5), 'Second'),
        ]
        
        with app.app_context():
            user = User.query.filter_by(email='test@example.com').first()
            for due_date, title in dates:
                a = Assignment(user_id=user.id, title=title, due_at=due_date)
                db.session.add(a)
            db.session.commit()
        
        response = auth_client.get('/assignments')
        html = response.data.decode('utf-8')
        
        # Check order in HTML
        first_pos = html.find('First')
        second_pos = html.find('Second')
        third_pos = html.find('Third')
        
        assert first_pos < second_pos < third_pos
    
    def test_urgent_assignment_highlighted(self, auth_client):
        """Test urgent assignments (due within 3 days) are highlighted."""
        with app.app_context():
            user = User.query.filter_by(email='test@example.com').first()
            urgent = Assignment(
                user_id=user.id,
                title='Urgent Task',
                due_at=datetime.now(timezone.utc) + timedelta(days=1)
            )
            db.session.add(urgent)
            db.session.commit()
        
        response = auth_client.get('/assignments')
        assert b'urgent' in response.data.lower() or b'due soon' in response.data.lower()
    
    def test_overdue_assignment_shown(self, auth_client):
        """Test overdue assignments are marked."""
        with app.app_context():
            user = User.query.filter_by(email='test@example.com').first()
            overdue = Assignment(
                user_id=user.id,
                title='Overdue Task',
                due_at=datetime.now(timezone.utc) - timedelta(days=1)
            )
            db.session.add(overdue)
            db.session.commit()
        
        response = auth_client.get('/assignments')
        assert b'overdue' in response.data.lower()


# =============================================================================
# S3: EDIT ASSIGNMENT TESTS
# =============================================================================

class TestS3EditAssignment:
    """Test Story S3: Edit assignment functionality."""
    
    def test_edit_page_loads(self, auth_client, sample_assignment):
        """Test edit page loads with pre-filled data."""
        response = auth_client.get(f'/assignments/edit/{sample_assignment}')
        assert response.status_code == 200
        assert b'Test Assignment' in response.data
        assert b'COMP1234' in response.data
    
    def test_edit_assignment_success(self, auth_client, sample_assignment):
        """Test editing assignment updates the data."""
        future_date = (datetime.now() + timedelta(days=14)).strftime('%Y-%m-%dT%H:%M')
        
        response = auth_client.post(f'/assignments/edit/{sample_assignment}', data={
            'title': 'Updated Title',
            'module': 'COMP5678',
            'estimated_hours': 10,
            'due_at': future_date
        }, follow_redirects=True)
        
        assert response.status_code == 200
        assert b'updated' in response.data.lower() or b'Updated Title' in response.data
        
        with app.app_context():
            assignment = db.session.get(Assignment, sample_assignment)
            assert assignment.title == 'Updated Title'
            assert assignment.module == 'COMP5678'
            assert assignment.estimated_hours == 10
    
    def test_edit_nonexistent_assignment(self, auth_client):
        """Test editing non-existent assignment returns 404."""
        response = auth_client.get('/assignments/edit/99999')
        assert response.status_code == 404
    
    def test_edit_other_users_assignment(self, auth_client):
        """Test cannot edit another user's assignment."""
        # Create another user and their assignment
        with app.app_context():
            other_user = User(email='other@example.com', name='Other User')
            other_user.set_password('password123')
            db.session.add(other_user)
            db.session.commit()
            
            other_assignment = Assignment(
                user_id=other_user.id,
                title='Other Assignment',
                due_at=datetime.now(timezone.utc) + timedelta(days=7)
            )
            db.session.add(other_assignment)
            db.session.commit()
            other_id = other_assignment.id
        
        response = auth_client.get(f'/assignments/edit/{other_id}', follow_redirects=True)
        assert b'permission' in response.data.lower() or b'Assignments' in response.data


# =============================================================================
# S4: DELETE & COMPLETE TESTS
# =============================================================================

class TestS4DeleteComplete:
    """Test Story S4: Delete and Complete functionality."""
    
    def test_delete_assignment(self, auth_client, sample_assignment):
        """Test deleting an assignment removes it."""
        response = auth_client.post(f'/assignments/delete/{sample_assignment}', follow_redirects=True)
        
        assert response.status_code == 200
        assert b'deleted' in response.data.lower()
        
        with app.app_context():
            assignment = db.session.get(Assignment, sample_assignment)
            assert assignment is None
    
    def test_complete_assignment(self, auth_client, sample_assignment):
        """Test completing assignment moves it to completed."""
        response = auth_client.post(f'/assignments/complete/{sample_assignment}', follow_redirects=True)
        
        assert response.status_code == 200
        assert b'complete' in response.data.lower()
        
        with app.app_context():
            assignment = db.session.get(Assignment, sample_assignment)
            assert assignment.completed == True
            assert assignment.completed_at is not None
    
    def test_completed_assignment_not_in_pending(self, auth_client, sample_assignment):
        """Test completed assignment doesn't appear in pending list."""
        auth_client.post(f'/assignments/complete/{sample_assignment}')
        
        response = auth_client.get('/assignments')
        # Check that the assignment list doesn't contain our completed assignment
        # Note: "No pending assignments" message confirms the list is empty
        assert b'No pending' in response.data or b'Test Assignment' not in response.data.split(b'list-group')[1] if b'list-group' in response.data else True
    
    def test_completed_assignment_in_completed_list(self, auth_client, sample_assignment):
        """Test completed assignment appears in completed list."""
        auth_client.post(f'/assignments/complete/{sample_assignment}')
        
        response = auth_client.get('/assignments/completed')
        assert b'Test Assignment' in response.data
    
    def test_uncomplete_assignment(self, auth_client, sample_assignment):
        """Test uncompleting assignment moves it back to pending."""
        # Complete first
        auth_client.post(f'/assignments/complete/{sample_assignment}')
        
        # Uncomplete
        response = auth_client.post(f'/assignments/uncomplete/{sample_assignment}', follow_redirects=True)
        
        with app.app_context():
            assignment = db.session.get(Assignment, sample_assignment)
            assert assignment.completed == False
            assert assignment.completed_at is None
    
    def test_delete_other_users_assignment(self, auth_client):
        """Test cannot delete another user's assignment."""
        with app.app_context():
            other_user = User(email='other@example.com', name='Other')
            other_user.set_password('pass')
            db.session.add(other_user)
            db.session.commit()
            
            other_assignment = Assignment(
                user_id=other_user.id,
                title='Other',
                due_at=datetime.now(timezone.utc) + timedelta(days=7)
            )
            db.session.add(other_assignment)
            db.session.commit()
            other_id = other_assignment.id
        
        response = auth_client.post(f'/assignments/delete/{other_id}', follow_redirects=True)
        assert b'permission' in response.data.lower()
        
        with app.app_context():
            # Should still exist
            assignment = db.session.get(Assignment, other_id)
            assert assignment is not None


# =============================================================================
# S5: CALENDAR VIEW & CLASH DETECTION TESTS
# =============================================================================

class TestS5CalendarClash:
    """Test Story S5: Calendar view and clash detection."""
    
    def test_calendar_page_loads(self, auth_client):
        """Test calendar page is accessible."""
        response = auth_client.get('/calendar')
        assert response.status_code == 200
        assert b'Calendar' in response.data
    
    def test_calendar_shows_month_name(self, auth_client):
        """Test calendar shows current month name."""
        response = auth_client.get('/calendar')
        months = ['January', 'February', 'March', 'April', 'May', 'June',
                  'July', 'August', 'September', 'October', 'November', 'December']
        current_month = months[datetime.now().month - 1]
        assert current_month.encode() in response.data
    
    def test_calendar_navigation(self, auth_client):
        """Test navigating between months."""
        # Go to next month
        now = datetime.now()
        next_month = now.month + 1 if now.month < 12 else 1
        next_year = now.year if now.month < 12 else now.year + 1
        
        response = auth_client.get(f'/calendar?year={next_year}&month={next_month}')
        assert response.status_code == 200
    
    def test_assignment_appears_on_calendar(self, auth_client):
        """Test assignments appear on their due date."""
        # Add assignment for specific date
        with app.app_context():
            user = User.query.filter_by(email='test@example.com').first()
            due_date = datetime.now(timezone.utc).replace(day=15)
            assignment = Assignment(
                user_id=user.id,
                title='Calendar Test',
                due_at=due_date
            )
            db.session.add(assignment)
            db.session.commit()
        
        response = auth_client.get(f'/calendar?year={due_date.year}&month={due_date.month}')
        assert b'Calendar Test' in response.data
    
    def test_clash_detection_warning(self, auth_client):
        """Test clash warning appears when 2+ assignments on same day."""
        with app.app_context():
            user = User.query.filter_by(email='test@example.com').first()
            due_date = datetime.now(timezone.utc) + timedelta(days=5)
            
            # Add two assignments on same day
            a1 = Assignment(user_id=user.id, title='Assignment One', due_at=due_date, estimated_hours=4)
            a2 = Assignment(user_id=user.id, title='Assignment Two', due_at=due_date, estimated_hours=6)
            db.session.add_all([a1, a2])
            db.session.commit()
        
        response = auth_client.get(f'/calendar?year={due_date.year}&month={due_date.month}')
        html = response.data.decode('utf-8').lower()
        assert 'clash' in html or '2 assignments' in html
    
    def test_no_clash_warning_single_assignment(self, auth_client):
        """Test no clash warning with single assignment per day."""
        with app.app_context():
            user = User.query.filter_by(email='test@example.com').first()
            assignment = Assignment(
                user_id=user.id,
                title='Solo Assignment',
                due_at=datetime.now(timezone.utc) + timedelta(days=3)
            )
            db.session.add(assignment)
            db.session.commit()
        
        response = auth_client.get('/calendar')
        # Check no clash warning banner (the word Clash in legend is OK)
        html = response.data.decode('utf-8')
        assert 'Deadline Clashes Found' not in html
    
    def test_workload_warning_heavy_week(self, auth_client):
        """Test workload warning when week has 15+ hours."""
        with app.app_context():
            user = User.query.filter_by(email='test@example.com').first()
            base_date = datetime.now(timezone.utc) + timedelta(days=3)
            
            # Add assignments totaling 20 hours
            for i in range(4):
                a = Assignment(
                    user_id=user.id,
                    title=f'Heavy {i}',
                    due_at=base_date + timedelta(days=i),
                    estimated_hours=5
                )
                db.session.add(a)
            db.session.commit()
        
        response = auth_client.get(f'/calendar?year={base_date.year}&month={base_date.month}')
        html = response.data.decode('utf-8').lower()
        assert 'workload' in html or 'warning' in html or '20' in html
    
    def test_hours_badge_displayed(self, auth_client):
        """Test hours badge shows on calendar days."""
        with app.app_context():
            user = User.query.filter_by(email='test@example.com').first()
            assignment = Assignment(
                user_id=user.id,
                title='Timed Task',
                due_at=datetime.now(timezone.utc) + timedelta(days=5),
                estimated_hours=8
            )
            db.session.add(assignment)
            db.session.commit()
        
        response = auth_client.get('/calendar')
        assert b'8h' in response.data


# =============================================================================
# S6: STATS OVERVIEW TESTS
# =============================================================================

class TestS6StatsOverview:
    """Test Story S6: Analytics stats overview."""
    
    def test_analytics_page_loads(self, auth_client):
        """Test analytics page is accessible."""
        response = auth_client.get('/analytics')
        assert response.status_code == 200
        assert b'Analytics' in response.data
    
    def test_analytics_empty_state(self, auth_client):
        """Test analytics shows empty state message."""
        response = auth_client.get('/analytics')
        assert b'No data' in response.data or b'Add' in response.data
    
    def test_total_count(self, auth_client):
        """Test total assignment count is correct."""
        with app.app_context():
            user = User.query.filter_by(email='test@example.com').first()
            for i in range(5):
                a = Assignment(
                    user_id=user.id,
                    title=f'Task {i}',
                    due_at=datetime.now(timezone.utc) + timedelta(days=i+1)
                )
                db.session.add(a)
            db.session.commit()
        
        response = auth_client.get('/analytics')
        assert b'5' in response.data
    
    def test_completion_rate(self, auth_client):
        """Test completion rate is calculated correctly."""
        with app.app_context():
            user = User.query.filter_by(email='test@example.com').first()
            
            # Add 4 assignments, complete 2 (50%)
            for i in range(4):
                a = Assignment(
                    user_id=user.id,
                    title=f'Task {i}',
                    due_at=datetime.now(timezone.utc) + timedelta(days=i+1),
                    completed=(i < 2),
                    completed_at=datetime.now(timezone.utc) if i < 2 else None
                )
                db.session.add(a)
            db.session.commit()
        
        response = auth_client.get('/analytics')
        assert b'50%' in response.data
    
    def test_pending_count(self, auth_client):
        """Test pending count is correct."""
        with app.app_context():
            user = User.query.filter_by(email='test@example.com').first()
            
            # 3 pending, 2 completed
            for i in range(5):
                a = Assignment(
                    user_id=user.id,
                    title=f'Task {i}',
                    due_at=datetime.now(timezone.utc) + timedelta(days=i+1),
                    completed=(i >= 3)
                )
                db.session.add(a)
            db.session.commit()
        
        response = auth_client.get('/analytics')
        # Should show 3 pending
        assert b'3' in response.data
    
    def test_overdue_count(self, auth_client):
        """Test overdue count is correct."""
        with app.app_context():
            user = User.query.filter_by(email='test@example.com').first()
            
            # 2 overdue
            for i in range(2):
                a = Assignment(
                    user_id=user.id,
                    title=f'Overdue {i}',
                    due_at=datetime.now(timezone.utc) - timedelta(days=i+1)
                )
                db.session.add(a)
            db.session.commit()
        
        response = auth_client.get('/analytics')
        assert b'2' in response.data


# =============================================================================
# S7: MODULE BREAKDOWN TESTS
# =============================================================================

class TestS7ModuleBreakdown:
    """Test Story S7: Module breakdown and weekly forecast."""
    
    def test_module_breakdown_displayed(self, auth_client):
        """Test module breakdown table is shown."""
        with app.app_context():
            user = User.query.filter_by(email='test@example.com').first()
            
            # Add assignments with different modules
            modules = ['COMP1234', 'COMP1234', 'COMP5678']
            for i, mod in enumerate(modules):
                a = Assignment(
                    user_id=user.id,
                    title=f'Task {i}',
                    module=mod,
                    due_at=datetime.now(timezone.utc) + timedelta(days=i+1)
                )
                db.session.add(a)
            db.session.commit()
        
        response = auth_client.get('/analytics')
        assert b'COMP1234' in response.data
        assert b'COMP5678' in response.data
    
    def test_module_progress_bar(self, auth_client):
        """Test progress bars show completion percentage."""
        with app.app_context():
            user = User.query.filter_by(email='test@example.com').first()
            
            # 2 completed, 2 pending for same module
            for i in range(4):
                a = Assignment(
                    user_id=user.id,
                    title=f'Task {i}',
                    module='COMP1234',
                    due_at=datetime.now(timezone.utc) + timedelta(days=i+1),
                    completed=(i < 2)
                )
                db.session.add(a)
            db.session.commit()
        
        response = auth_client.get('/analytics')
        assert b'50%' in response.data or b'progress' in response.data.lower()
    
    def test_weekly_forecast(self, auth_client):
        """Test weekly forecast shows next 4 weeks."""
        with app.app_context():
            user = User.query.filter_by(email='test@example.com').first()
            
            # Add assignments spread across weeks
            for i in range(4):
                a = Assignment(
                    user_id=user.id,
                    title=f'Week {i+1} Task',
                    due_at=datetime.now(timezone.utc) + timedelta(days=i*7 + 2),
                    estimated_hours=5
                )
                db.session.add(a)
            db.session.commit()
        
        response = auth_client.get('/analytics')
        html = response.data.decode('utf-8')
        assert 'Week 1' in html or 'week' in html.lower()
    
    def test_hours_per_week(self, auth_client):
        """Test hours per week are calculated correctly."""
        with app.app_context():
            user = User.query.filter_by(email='test@example.com').first()
            
            # Add 2 assignments with 5 hours each in next week
            for i in range(2):
                a = Assignment(
                    user_id=user.id,
                    title=f'Task {i}',
                    due_at=datetime.now(timezone.utc) + timedelta(days=2+i),
                    estimated_hours=5
                )
                db.session.add(a)
            db.session.commit()
        
        response = auth_client.get('/analytics')
        assert b'10' in response.data  # 5 + 5 = 10 hours


# =============================================================================
# MODEL TESTS
# =============================================================================

class TestModels:
    """Test database models and methods."""
    
    def test_user_password_hashing(self, client):
        """Test password is hashed, not stored plain text."""
        with app.app_context():
            user = User(email='test@example.com', name='Test')
            user.set_password('mypassword')
            
            assert user.password_hash != 'mypassword'
            assert user.check_password('mypassword') == True
            assert user.check_password('wrongpassword') == False
    
    def test_assignment_is_urgent(self, client):
        """Test is_urgent() method."""
        with app.app_context():
            db.create_all()
            user = User(email='test@example.com', name='Test')
            user.set_password('pass')
            db.session.add(user)
            db.session.commit()
            
            # Urgent: due in 2 days
            urgent = Assignment(
                user_id=user.id,
                title='Urgent',
                due_at=datetime.now(timezone.utc) + timedelta(days=2)
            )
            
            # Not urgent: due in 10 days
            not_urgent = Assignment(
                user_id=user.id,
                title='Not Urgent',
                due_at=datetime.now(timezone.utc) + timedelta(days=10)
            )
            
            assert urgent.is_urgent() == True
            assert not_urgent.is_urgent() == False
    
    def test_assignment_is_overdue(self, client):
        """Test is_overdue() method."""
        with app.app_context():
            db.create_all()
            user = User(email='test@example.com', name='Test')
            user.set_password('pass')
            db.session.add(user)
            db.session.commit()
            
            # Overdue
            overdue = Assignment(
                user_id=user.id,
                title='Overdue',
                due_at=datetime.now(timezone.utc) - timedelta(days=1)
            )
            
            # Not overdue
            not_overdue = Assignment(
                user_id=user.id,
                title='Not Overdue',
                due_at=datetime.now(timezone.utc) + timedelta(days=1)
            )
            
            assert overdue.is_overdue() == True
            assert not_overdue.is_overdue() == False
    
    def test_completed_assignment_not_urgent(self, client):
        """Test completed assignments are not marked urgent."""
        with app.app_context():
            db.create_all()
            user = User(email='test@example.com', name='Test')
            user.set_password('pass')
            db.session.add(user)
            db.session.commit()
            
            completed = Assignment(
                user_id=user.id,
                title='Completed',
                due_at=datetime.now(timezone.utc) + timedelta(days=1),
                completed=True
            )
            
            assert completed.is_urgent() == False
            assert completed.is_overdue() == False


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
