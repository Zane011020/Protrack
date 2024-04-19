from flask import Flask, render_template, request, redirect, url_for, flash,session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_, and_
from flask_migrate import Migrate
from flask_login import LoginManager, current_user, login_required, login_user, UserMixin, logout_user
from datetime import datetime
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask import jsonify
import secrets
from flask_mail import Message, Mail
import flask_mail

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'SECRET_KEY'


app.config['MAIL_SERVER'] = 'smtp.office365.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'chengzhao120@outlook.com'
app.config['MAIL_PASSWORD'] = 'Wshnb666..'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEFAULT_SENDER'] = 'chengzhao120@outlook.com'



db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
mail = Mail(app)
login_manager.login_view = 'login'

group_project = db.Table('group_project',
    db.Column('group_id', db.Integer, db.ForeignKey('groups.id'), primary_key=True),
    db.Column('project_id', db.Integer, db.ForeignKey('projects.id'), primary_key=True)
)

class Group(db.Model):
    __tablename__ = 'groups'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    group_members = db.relationship('GroupMember', backref='group', lazy=True)
    projects = db.relationship('Project', secondary=group_project, backref=db.backref('groups', lazy=True))
    
class GroupMember(db.Model):
    __tablename__ = 'group_members'
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'))
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User', foreign_keys=[student_id])

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'),nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_sent = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User')
    group = db.relationship('Group', backref='messages')

class Project(db.Model):
    __tablename__ = 'projects'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)
    description = db.Column(db.Text)
    start_date = db.Column(db.Date, nullable=False)
    instructor_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    instructor = db.relationship('User', foreign_keys=[instructor_id])
    tasks = db.relationship('Task', backref='project', lazy='dynamic')
    status = db.Column(db.Enum('In Progress', 'Completed'), default='In Progress', nullable=False)

class GroupProjectRating(db.Model):
    __tablename__ = 'group_project_ratings'
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    rating = db.Column(db.Float)

    group = db.relationship('Group', backref='ratings')
    project = db.relationship('Project', backref='ratings')



class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    description = db.Column(db.Text)
    start_date = db.Column(db.Date)
    end_date = db.Column(db.Date)
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'),nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'),nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('groups.id'),nullable=False)
    status = db.Column(db.Enum('Not Started', 'In Progress', 'Completed'), default='Not Started', nullable=False)
    user = db.relationship('User', backref='assigned_tasks')
    group = db.relationship('Group', backref='tasks')

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    role = db.Column(db.Enum('Student', 'Teacher'), nullable=False)
    profile = db.Column(db.String(255), nullable=False, default='profile.jpg')
    full_name = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text, nullable=True)
    reset_tokens = db.relationship('PasswordResetToken', back_populates='user')
    def check_password(self, password):
        return check_password_hash(self.password, password)
    def set_password(self, password):
        self.password = generate_password_hash(password)

class PasswordResetToken(db.Model):
    __tablename__ = 'password_reset_tokens'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token = db.Column(db.String(256), nullable=False, unique=True)
    expires_at = db.Column(db.DateTime, nullable=False)

    user = db.relationship('User', back_populates='reset_tokens')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    if current_user.role == 'Teacher':
        instructor_projects = Project.query.filter_by(instructor_id=current_user.id).all()
        return render_template('index_teacher.html', active_page='dashboard', projects=instructor_projects)
    else:
        current_user_groups = Group.query.join(GroupMember, Group.id == GroupMember.group_id)\
                                        .filter(GroupMember.student_id == current_user.id)\
                                        .all()
        group_projects = {}
        group_projects_tasks = {}
        for group in current_user_groups:
            group_projects[group] = group.projects


            projects_tasks = {}
            
            for project in group.projects:

                tasks = Task.query.filter(Task.project_id == project.id, Task.group_id == group.id).all()
                projects_tasks[project] = tasks

            group_projects_tasks[group] = projects_tasks


        return render_template('index.html', active_page='dashboard', current_user_groups=current_user_groups,group_projects=group_projects, group_projects_tasks=group_projects_tasks)
@app.route('/contact')
def contact():
    return render_template('pages-contact.html', active_page='contact')
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if request.method == 'POST':
        if 'update_profile' in request.form:
            full_name = request.form.get('fullName')
            email = request.form.get('email')
            description = request.form.get('description')

            current_user.full_name = full_name
            current_user.email = email
            current_user.description = description
            db.session.commit()

            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
        elif 'change_password' in request.form:
            current_password = request.form.get('password')
            new_password = request.form.get('newpassword')
            renew_password = request.form.get('renewpassword')
            print(1)
            if not current_user.check_password(current_password):
                flash('Current password is incorrect.', 'danger')
                return redirect(url_for('profile'))

            if new_password != renew_password:
                flash('New passwords do not match.', 'danger')
                return redirect(url_for('profile'))

            current_user.set_password(new_password)
            db.session.commit()

            flash('Your password has been updated!', 'success')
            return redirect(url_for('profile'))
    return render_template('users-profile.html', active_page='profile')

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if current_user.role == 'Teacher':

        if request.method == 'POST':
            if 'sendMessage' in request.form:
                content = request.form.get('messageContent')
                group_id = request.form.get('groupName')
                if content:
                    new_message = Message(
                        group_id=group_id, 
                        user_id=current_user.id,
                        content=content,
                        date_sent=datetime.utcnow()
                    )
                    db.session.add(new_message)
                    db.session.commit()
                    flash('Feedback sent successfully!', 'success')
                else:
                    flash('Feedback content cannot be empty.', 'danger')

                return redirect(url_for('feedback'))
        feedback_messages = []
    
        feedback_messages = Message.query.filter_by(user_id=current_user.id).order_by(Message.date_sent.desc()).all()
        groups = Group.query.join(Project, Group.projects).filter(Project.instructor_id == current_user.id).all()
        
        return render_template('feedback.html', active_page='feedback' , feedback_messages=feedback_messages, groups=groups)

@app.route('/rating', methods=['GET', 'POST'])
def rating():
    if current_user.role != 'Teacher':
        return "Access Denied", 403

    projects = Project.query.filter_by(instructor_id=current_user.id).all()
    existing_score = None
    if request.method == 'POST':
        selected_project_id = request.form.get('selectedProject')
        selected_group_id = request.form.get('selectedGroup')
        score = request.form.get('score')
        
        existing_rating = GroupProjectRating.query.filter_by(group_id=selected_group_id, project_id=selected_project_id).first()
        if existing_rating:
            existing_score = existing_rating.rating
        if existing_rating:
            existing_rating.rating = score
        else:
            new_rating = GroupProjectRating(group_id=selected_group_id, project_id=selected_project_id, rating=score)
            db.session.add(new_rating)
        
        db.session.commit()
        flash('Score submitted successfully!', 'success')
             
    return render_template('rating.html', active_page='rating', projects=projects, existing_score=existing_score)

@app.route('/get_groups_by_project/<int:project_id>')
def get_groups_by_project(project_id):
    groups = Group.query.filter(Group.projects.any(id=project_id)).all()
    groups_data = [{'id': group.id, 'name': group.name} for group in groups]
    return jsonify({'groups': groups_data})

@app.route('/get_group_score/<int:project_id>/<int:group_id>')
def get_group_score(project_id, group_id):
    rating = GroupProjectRating.query.filter_by(group_id=group_id, project_id=project_id).first()
    score = rating.rating if rating else ''
    return jsonify({'score': score})



@app.route('/detail', methods=['GET', 'POST'])
def detail():
    if current_user.role == 'Teacher':
        projects = Project.query.filter_by(instructor_id=current_user.id).all() 
        selected_project_id = request.form.get('projectName') if request.method == 'POST' else request.args.get('project')
        selected_project = Project.query.get(selected_project_id) if selected_project_id else None

        groups_tasks = {}
        groups_members = {}
        groups_ratings = {}
        if selected_project:
            groups = Group.query.filter(Group.projects.any(id=selected_project.id)).all()
            for group in groups:
                tasks = Task.query.filter_by(group_id=group.id, project_id=selected_project.id).all()
                groups_tasks[group] = tasks
                members = User.query.join(GroupMember).filter(GroupMember.group_id == group.id).all()
                groups_members[group] = members
                rating = GroupProjectRating.query.filter_by(group_id=group.id, project_id=selected_project.id).first()
                groups_ratings[group] = rating.rating if rating else "Not rated"

    
        return render_template('projectdetail2.html', active_page='detail', projects=projects, selected_project=selected_project, groups_tasks=groups_tasks, groups_members=groups_members, groups_ratings=groups_ratings)
    
    user_groups = Group.query.join(GroupMember, Group.id == GroupMember.group_id)\
                                      .filter(GroupMember.student_id == current_user.id)\
                                      .all()
    projects = set()
    for group in user_groups:
        for project in group.projects:
            projects.add(project)

    selected_project = None
    selected_group = None
    messages = []
    groups_ratings = {}
    if request.method == 'POST':
        selected_project_id = request.form.get('projectName')
        selected_project = Project.query.get(selected_project_id)
        for group in user_groups:
            if selected_project in group.projects:
                selected_group = group
                break
        for group in user_groups:
            rating = GroupProjectRating.query.filter_by(group_id=group.id, project_id=selected_project.id).first()
            groups_ratings[group] = rating.rating if rating else "Not rated"
        if selected_group:
            messages = Message.query.filter_by(group_id=selected_group.id).join(User).filter(User.role == 'Teacher').all()

    tasks = Task.query.filter_by(project_id=selected_project.id, group_id=selected_group.id).all() if selected_project and selected_group else []


    return render_template('projectdetail.html', active_page='detail', projects=projects, selected_project=selected_project, tasks=tasks,group=selected_group, groups_ratings=groups_ratings, messages=messages)
@app.route('/process', methods=['GET', 'POST'])
def process():
    if current_user.role == 'Teacher':
        return redirect(url_for('index'))
    else:
        user_groups = Group.query.join(GroupMember, Group.id == GroupMember.group_id)\
                                .filter(GroupMember.student_id == current_user.id)\
                                .all()
        projects = set()
        for group in user_groups:
            for project in group.projects:
                projects.add(project)
        
        if request.method == 'POST':
            project_id = request.form.get('projectName')
            task_id = request.form.get('taskName')
            new_status = request.form.get('taskProgress')

            task = Task.query.join(Group, Task.group_id == Group.id)\
                            .join(GroupMember, Group.id == GroupMember.group_id)\
                            .filter(Task.id == task_id, GroupMember.student_id == current_user.id)\
                            .first()
            if task:
                task.status = new_status
                db.session.commit()
                flash('Task progress updated successfully!', 'success')
            else:
                flash('Task not found.', 'danger')

        return render_template('projectprogress.html', active_page='process', projects=projects)
@app.route('/get_tasks_by_project/<int:project_id>')
def get_tasks_by_project(project_id):
    tasks = Task.query.join(Group, Task.group_id == Group.id)\
                      .join(GroupMember, Group.id == GroupMember.group_id)\
                      .filter(Task.project_id == project_id, GroupMember.student_id == current_user.id)\
                      .all()
    tasks_data = [{'id': task.id, 'name': task.name} for task in tasks]
    return jsonify({'tasks': tasks_data})
@app.route('/get_completed_tasks/<int:project_id>')
def get_completed_tasks(project_id):
    completed_tasks = Task.query.filter_by(project_id=project_id, status='Completed').all()
    tasks_data = [{'id': task.id, 'name': task.name, 'due_date': task.end_date.strftime('%Y-%m-%d')} for task in completed_tasks]
    return jsonify({'tasks': tasks_data})


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['Username']
        password = request.form['Password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            session['logged_in'] = True
            session['username'] = user.username
            session['role'] = user.role
            session['email'] = user.email
            session['profile'] = user.profile
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', active_page='login')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('Username')
        password = request.form.get('Password')
        email = request.form.get('Email')
        role = request.form.get('Role')
        if not username or not email or not password:
            flash('Please fill out all fields', 'danger')
            return redirect(url_for('register'))
        
        existing_user = User.query.filter(or_(User.email == email, User.username == username)).first()
        if existing_user:
            if existing_user.email == email:
                flash('Email already in use', 'danger')
            elif existing_user.username == username:
                flash('Username already taken', 'danger')
            return redirect(url_for('register'))       
        
        password_hash = generate_password_hash(password)
        new_user = User(username=username, password=password_hash, email=email, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', active_page='register')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['Email']
        user = User.query.filter_by(email=email).first()
        if user:

            token = secrets.token_urlsafe()

            expiration_time = datetime.utcnow() + timedelta(hours=1)
            reset_token = PasswordResetToken(user_id=user.id, token=token, expires_at=expiration_time)
            db.session.add(reset_token)
            db.session.commit()


            msg = flask_mail.Message('Password Reset Request',  recipients=[user.email])
            link = url_for('reset_password', token=token, _external=True)
            msg.body = f'Your link to reset password is {link}'
            mail.send(msg)
            
            flash('Please check your email for a password reset link.', 'info')
            return redirect(url_for('login'))
        else:
            flash('This email does not exist in our records.', 'danger')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset_token = PasswordResetToken.query.filter(
    and_(PasswordResetToken.token == token, PasswordResetToken.expires_at >= datetime.utcnow())
).first()
    if not reset_token:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))
    
    user = User.query.get(reset_token.user_id)
    
    if request.method == 'POST':
        user.password = generate_password_hash(request.form['password'])
        db.session.commit()
        flash('Your password has been updated.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/project_member_contact', methods=['GET', 'POST'])
def projectmember_contact():
    if current_user.role == 'Teacher':
        return redirect(url_for('index'))
    else:
        groups = Group.query.join(GroupMember).filter(GroupMember.student_id == current_user.id).all()
        selected_group_id = request.args.get('selectedGroup', type=int) 

        if request.method == 'POST':
            selected_group_id = request.form.get('selectedGroup', type=int) 

            if 'sendMessage' in request.form:
                content = request.form.get('messageContent')

                if selected_group_id and content:
                    new_message = Message(group_id=selected_group_id, user_id=current_user.id, content=content, date_sent=datetime.utcnow())
                    db.session.add(new_message)
                    db.session.commit()
                    flash('Message sent successfully!', 'success')
                else:
                    if not selected_group_id:
                        flash('Please select a group first.', 'danger')
                    if not content:
                        flash('Message content cannot be empty.', 'danger')
            elif 'assignTask' in request.form:
                
                task_name = request.form.get('taskName')
                task_description = request.form.get('taskDescription')
                start_date = request.form.get('startDate')
                end_date = request.form.get('endDate')
                assigned_to = request.form.get('assignedTo')
                projectId = request.form.get('projectId')
                if not all([assigned_to, task_name, start_date, end_date]):
                    flash('Please fill out all fields for task assignment.', 'danger')
                elif selected_group_id:
                    new_task = Task(
                        name=task_name,
                        description=task_description,
                        start_date=datetime.strptime(start_date, '%Y-%m-%d'),
                        end_date=datetime.strptime(end_date, '%Y-%m-%d'),
                        assigned_to=assigned_to,
                        project_id=projectId,
                        group_id=selected_group_id
                    )
                    db.session.add(new_task)
                    db.session.commit()
                    print(assigned_to)
                    flash('Task assigned successfully!', 'success')
                else:
                    flash('Please select a group first.', 'danger')
        print(selected_group_id)
        selected_group = Group.query.get(selected_group_id) if selected_group_id else None
        members = selected_group.group_members if selected_group else []
        messages = Message.query.join(User).filter(Message.group_id == selected_group_id, User.role == 'Student').all () if selected_group_id else []
        tasks = Task.query.filter_by(group_id=selected_group_id).all() if selected_group_id else []
        projects = selected_group.projects if selected_group else []

        return render_template('projectmember_contact.html', active_page='projectmember_contact', groups=groups, members=members, messages=messages, selected_group=selected_group, tasks=tasks, projects=projects)

@app.route('/manage_members', methods=['GET', 'POST'])
def ManageGroupMembers():
    if current_user.role == 'Teacher':
        return redirect(url_for('index'))
    else:
        if request.method == 'POST':
            member_username = request.form.get('memberUsername')
            group_id = request.form.get('memberGroup')

            user = User.query.filter_by(username=member_username).first()
            existing_member = GroupMember.query.filter_by(group_id=group_id, student_id=user.id).first()
            if existing_member:
                flash('Member is already in the group', 'warning')
                return redirect(url_for('ManageGroupMembers'))
            if user:
                new_member = GroupMember(group_id=group_id, student_id=user.id)
                db.session.add(new_member)
                db.session.commit()
                flash('Member added successfully!', 'success')
            else:
                flash('User not found.', 'danger')

        users = User.query.filter_by(role='Student').all()
        groups = Group.query.filter(Group.group_members.any(student_id=current_user.id)).all()
        return render_template('ManageGroupMembers.html', active_page='ManageGroupMembers', users=users, groups=groups, current_user_id=current_user.id)
@app.route('/get_group_members/<int:group_id>')
def get_group_members(group_id):
    group = Group.query.get(group_id)
    members = [{'id': gm.student_id, 'username': User.query.get(gm.student_id).username} for gm in group.group_members]
    return jsonify({'members': members})
@app.route('/remove_group_member/<int:member_id>/<int:group_id>', methods=['POST'])
@login_required
def remove_group_member(member_id, group_id):

    group_member = GroupMember.query.filter_by(group_id=group_id, student_id=member_id).first()
    
    if group_member:
        db.session.delete(group_member)
        db.session.commit()
        flash('Member removed successfully', 'success')

    else:
        flash('Member not found', 'danger')
    return redirect(url_for('ManageGroupMembers'))
@app.route('/leave_group/<int:group_id>', methods=['POST'])
@login_required
def leave_group(group_id):
    group_member = GroupMember.query.filter_by(group_id=group_id, student_id=current_user.id).first()
    
    if group_member:
        db.session.delete(group_member)
        db.session.commit()
        flash('You have successfully left the group.', 'success')
    else:
        flash('You are not a member of this group.', 'warning')

    return redirect(url_for('ManageGroupMembers')) 

@app.route('/manage_groups', methods=['GET', 'POST'])
def ManageGroups():
    if current_user.role == 'Teacher':
        return redirect(url_for('index'))
    else:
        if request.method == 'POST':
            group_name = request.form.get('GroupName')
            project_id = request.form.get('ProjectName')
            group_members_ids = set(request.form.getlist('GroupMembers[]')) | {current_user.id}
            
            existing_group = Group.query.filter(Group.name == group_name).first()
            if existing_group:
                flash('Group name already in use', 'danger')
                return redirect(url_for('ManageGroups'))
            
            for member_id in group_members_ids:
                member_groups = Group.query.join(GroupMember).filter(GroupMember.student_id == member_id).all()
                for group in member_groups:
                    if int(project_id) in [project.id for project in group.projects]:
                        member = User.query.get(member_id)
                        flash(f'{member.username} is already in a group working on this project.', 'danger')
                        return redirect(url_for('ManageGroups'))
            
            new_group = Group(name=group_name)
            db.session.add(new_group)
            db.session.commit()

            for member_id in group_members_ids:
                group_member = GroupMember(group_id=new_group.id, student_id=member_id)
                db.session.add(group_member)

            project = Project.query.get(project_id)
            if project:
                new_group.projects.append(project)
            db.session.commit()

            flash('New group created successfully!', 'success')
            return redirect(url_for('ManageGroups'))
        
        projects = Project.query.all()
        members = User.query.filter_by(role='Student').all()

        return render_template('ManageGroups.html', active_page='ManageGroups',  projects=projects, members=members)

@app.route('/create_new_project', methods=['GET', 'POST'])
def CreateNewProject():
    if request.method == 'POST':
        project_name = request.form.get('ProjectName')
        project_description = request.form.get('ProjectDescription')
        start_date_str = request.form.get('StartDate')
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        if current_user.role != 'Teacher':
            instructor_id = request.form.get('InstructorID')
        else:
            instructor_id= current_user.id
        
        new_project = Project(
                name=project_name,
                description=project_description,
                start_date=start_date,
                instructor_id=instructor_id
            )
        
        existing_project = Project.query.filter(Project.name == project_name).first()
        if existing_project:
            flash('Project name already in use', 'danger')
            return redirect(url_for('CreateNewProject'))
        db.session.add(new_project)
        db.session.commit()

        flash('New project created successfully!', 'success')
        return redirect(url_for('CreateNewProject'))

    instructors = User.query.filter_by(role='Teacher').all()
    return render_template('CreateNewProject.html', active_page='CreateNewProject', instructors=instructors)
if __name__ == '__main__':
    app.run(debug=True)
