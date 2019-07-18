import time
import urllib
from datetime import datetime, timedelta
import gc
import json
import uuid
import re
import base64
import hmac
import hashlib
from functools import wraps
from io import BytesIO
from flask import Flask, render_template, url_for, request, redirect, session, flash, abort, send_file, jsonify
from google.appengine.api import urlfetch, mail, memcache
from google.appengine.ext import blobstore
from werkzeug import http
from app_settings import *
from forms import *
from models import *

app = Flask(__name__)
app.config['SECRET_KEY'] = '586d4f92e93f985f6ceb58729938c52e'
app.config['DEBUG'] = True


############################################################
# DECORATORS
# Check the user's role from the datastore, also checks if user is logged in,
def permission_required(accepted_roles):
    def permission(f):
        @wraps(f)
        def wrap(*args, **kwargs):
            # First check if the user is logged in
            if session.get('Logged_In', False):
                user_data = login(session.get('UserID'))
                # Check if the user account is still active
                if not user_data.AccountDetails.is_active:
                    session.clear()
                    gc.collect()
                    flash('Your account is longer active. Please contact IT Services to regain access.', 'danger')
                    return redirect(url_for('login_page'))
                # Get some basic user information
                kwargs['first_name'] = user_data.PersonalDetails.first_name
                kwargs['faculty'] = user_data.AccountDetails.faculty
                kwargs['last_name'] = user_data.PersonalDetails.last_name
                if user_data.AccountDetails.is_admin:
                    kwargs['user_role'] = "Admin"
                elif user_data.AccountDetails.is_tutor:
                    kwargs['user_role'] = "Tutor"
                else:
                    kwargs['user_role'] = "Student"
                    kwargs['student_id'] = user_data.PersonalDetails.student_number
                if kwargs['user_role'] in accepted_roles:
                    return f(*args, **kwargs)
                abort(403)
            else:
                abort(401)
            return f(*args, **kwargs)

        return wrap
    return permission


############################################################
# JINJA2 CUSTOM FILTERS
# Decodes base64
def reverse_b64(s):
    if isinstance(s, str):
        s = s.decode('utf-8').strip()
    return base64.b64decode(s)


app.jinja_env.filters['b64'] = reverse_b64


############################################################
# UNAUTHORISED VIEWS
# Login Page:
@app.route('/', methods=['GET', 'POST'])
@app.route('/Login', methods=['GET', 'POST'])
def login_page():
    if session.get('Logged_In'):
        return redirect(url_for('my_dashboard'))

    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            attempted_email = request.form.get('email').lower()
            attempted_password = request.form.get('password')
            if check_login(attempted_email, attempted_password):
                return redirect(url_for('my_dashboard'))
    return render_template('html/Unauthenticated/Login.html', page_title="Login", form=form, bg_image=get_bg())


# Register Page:
@app.route('/Register', methods=['GET', 'POST'])
def register_page():
    faculty_choices = [(faculty.key.id(), faculty.faculty_name) for faculty in
                       Faculty.query(Faculty.is_Active == True).fetch(projection=[Faculty.faculty_name])]

    form = RegistrationForm()
    form.faculty.choices = faculty_choices
    if request.method == 'POST':
        resp = api_launcher("POST", "https://www.google.com/recaptcha/api/siteverify",
                            {"secret": RECAPTCHA_SECRET,
                             "response": request.form.get("g-recaptcha-response"),
                             "remoteip": request.remote_addr
                             })
        if resp['success']:
            if form.validate_on_submit():
                first_name = form.first_name.data
                faculty = form.faculty.data
                last_name = form.last_name.data
                student_number = form.student_number.data
                graduation_date = datetime.strptime(str(form.graduation_date.data), '%Y-%m-%d')
                mobile_number = form.mobile_number.data.replace(' ', '')
                # Change "Bournemouth.ac.uk" to any domain you require.
                university_email = form.student_number.data + "@bournemouth.ac.uk"
                password = form.password.data
                if register(first_name, last_name, student_number, graduation_date, mobile_number,
                            university_email,
                            password, faculty):
                    flash('Account successfully created, please check email to verify.', 'success')
                    return redirect(url_for('login_page'))
        else:
            flash('Please tick the reCAPTCHA box.', 'warning')

    return render_template('html/Unauthenticated/Register.html', page_title="Register", form=form, bg_image=get_bg())


# Password Reset:
@app.route('/ResetPassword', methods=['GET', 'POST'])
def reset_password():
    email = request.args.get('email')
    code = request.args.get('code')
    form = PasswordResetForm()
    if not email or not code:
        flash('Error Occurred: Url is invalid.', 'danger')
        return redirect(url_for('login_page'))

    q = PasswordReset.query(
        PasswordReset.university_email == email.lower(),
        PasswordReset.verification_hash == code,
    )

    if q.count() != 1:
        flash('Code already used or has expired.', 'danger')
        return redirect(url_for('login_page'))

    if request.method == 'POST':
        if form.validate_on_submit():
            q.get().key.delete()
            user = login(email)
            user.AccountDetails.verified_status = True
            user.AccountDetails.is_active = True
            user.AccountDetails.password = hash_me(request.form.get('password'))
            user.put()
            flash('Password successfully changed.', 'success')
            return redirect(url_for('login_page'))
    return render_template('html/Unauthenticated/ResetPassword.html', page_title="Reset Password", form=form,
                           bg_image=get_bg())


@app.route('/verify', methods=['GET', 'POST'])
def verify_email():
    email = str(request.args.get('email'))
    code = request.args.get('code')

    q = UserDetails.query(
        UserDetails.AccountDetails.university_email == email.lower(),
        UserDetails.AccountDetails.verification_hash == code,
        UserDetails.AccountDetails.verified_status == False
    )

    if q.count() == 1:
        user = login(email)
        user.AccountDetails.verified_status = True
        user.AccountDetails.is_active = True
        user.put()
        flash('Email Verified! Please log in to access the site.', 'success')
    else:
        flash('Error Occurred: Url is invalid or email already verified.', 'danger')
    return redirect(url_for('login_page'))


############################################################
# GOOGLE OAUTH VIEWS
# Log into Google
@app.route('/GoogleLogin', methods=['GET', 'POST'])
def google_login():
    if not request.args.get("code"):
        url_endpoint = "https://accounts.google.com/o/oauth2/v2/auth?"
        params = {
            "redirect_uri": request.url_root + url_for('google_login').replace("/", ""),
            "prompt": "consent",
            "response_type": "code",
            "client_id": CLIENT_ID,
            "scope": "https://www.googleapis.com/auth/plus.me+" +
                     "https://www.googleapis.com/auth/userinfo.email+" +
                     "https://www.googleapis.com/auth/userinfo.profile+",
            "access_type": "offline"
        }
        return redirect(url_endpoint + urllib.urlencode(params).replace("%2B", "+"))
    else:
        auth_token = request.args.get("code")
        user_tokens = get_user_token(auth_token)
        access_token = user_tokens['access_token']
        refresh_token = user_tokens['refresh_token']
        user_details = oauth_launcher("GET", "https://www.googleapis.com/userinfo/v2/me", None, access_token)

        if oAuthLogins.query(oAuthLogins.google_id == user_details['id']).count() == 0:
            # New User
            registration_data = oAuthLogins(
                google_id=user_details['id'],
                access_token=access_token,
                refresh_token=refresh_token
            )
            if session.get('UserID'):
                registration_data.user_key = login(session.get('UserID')).key
            registration_data.put()
        else:
            # Old User
            registration_data = oAuthLogins.query(oAuthLogins.google_id == user_details['id']).get()
            registration_data.access_token = access_token
            # With User Linked
            if registration_data.user_key:
                user_account = UserDetails.get_by_id(registration_data.user_key.id())
                if not user_account.AccountDetails.verified_status:
                    flash('Please check your email to verify your account before use.', 'danger')
                    return redirect(url_for('login_page'))
                else:
                    session['Logged_In'] = True
                    session['UserID'] = user_account.AccountDetails.university_email.lower()
                    return redirect(url_for('my_dashboard'))
    if session.get('UserID'):
        flash('Account successfully linked with Google!', 'success')
        time.sleep(1)
        return redirect(url_for('settings'))
    else:
        session['GoogleData'] = {
            "First": user_details['given_name'],
            "Surname": user_details['family_name'],
            "oAuth": registration_data.key.id()
        }
        return redirect(url_for('google_register'))


# Remove OAuth Data
@app.route('/GoogleDisable', methods=['GET', 'POST'])
def google_disable():
    if session.get("UserID"):
        user_data = login(session.get('UserID'))
        oauth = oAuthLogins.query(oAuthLogins.user_key == user_data.key).get()
        if oauth:
            oauth.key.delete()
    flash("Google has been disassociated from your account.", "success")
    return redirect(url_for('settings'))


@app.route('/GoogleRegister', methods=['GET', 'POST'])
def google_register():
    if not session.get('GoogleData'):
        return redirect(url_for('register_page'))
    form = GoogleRegistrationForm()
    faculty_choices = [(faculty.key.id(), faculty.faculty_name) for faculty in
                       Faculty.query(Faculty.is_Active == True).fetch(projection=[Faculty.faculty_name])]
    form.faculty.choices = faculty_choices
    if form.validate_on_submit():
        student_number = form.student_number.data
        graduation_date = datetime.strptime(str(form.graduation_date.data), '%Y-%m-%d')
        faculty = form.faculty.data
        mobile_number = form.mobile_number.data.replace(' ', '')
        # Change "Bournemouth.ac.uk" to any domain you require.
        university_email = form.student_number.data + "@bournemouth.ac.uk"
        first_name = session.get('GoogleData')["First"]
        last_name = session.get('GoogleData')["Surname"]
        password = uuid.uuid4().hex
        register_attempt = register(first_name, last_name, student_number, graduation_date, mobile_number,
                                    university_email,
                                    password, faculty)
        if register_attempt:
            oAuthRecord = oAuthLogins.get_by_id(session.get('GoogleData')["oAuth"])
            oAuthRecord.user_key = register_attempt.key
            oAuthRecord.put()
            session.clear()
            gc.collect()
            flash('Account successfully created, please check email to verify.', 'success')
            return redirect(url_for('login_page'))

    return render_template('html/Unauthenticated/GoogleRegister.html', form=form, bg_image=get_bg())


def get_user_token(auth_code):
    resp = api_launcher("POST", "https://www.googleapis.com/oauth2/v4/token",
                        {"code": auth_code,
                         "redirect_uri": request.url_root + url_for('google_login').replace("/", ""),
                         "client_id": CLIENT_ID,
                         "client_secret": CLIENT_SECRET,
                         "scope": "",
                         "grant_type": "authorization_code"
                         }
                        )
    return resp


############################################################
# Authorised VIEWS
# Logout Page:
@app.route('/Logout', methods=['GET', 'POST'])
@permission_required({"Student", "Tutor", "Admin"})
def logout(**kwargs):
    session.clear()
    gc.collect()
    flash("Successfully Logged Out!", "success")
    return redirect(url_for('login_page'))


# Dashboard:
@app.route("/Dashboard", methods=['GET', 'POST'])
@permission_required({"Student", "Tutor", "Admin"})
def my_dashboard(**kwargs):
    user_requests = None
    if kwargs['user_role'] == "Student":
        user_requests = Requests.query(Requests.university_email == session.get("UserID")).order(
            -Requests.update_date).fetch()

    if kwargs['user_role'] == "Tutor":
        user_requests = Requests.query(Requests.faculty == kwargs['faculty']).order(
            -Requests.update_date).fetch()

    if kwargs['user_role'] != "Admin":
        request_data_list = [request_item._to_dict() for request_item in user_requests]

        index = 0
        for request_data in request_data_list:
            request_extra_data = (
                {
                    "unit": Unit.get_by_id(user_requests[index].unit.id()).unit_name,
                    "id": user_requests[index].key.id()
                })
            request_data.update(request_extra_data)
            index += 1
    else:
        request_data_list = {}

    return render_template('html/Dashboard/Index.html', requests=request_data_list,
                           navigation_bar=nav_bar[kwargs['user_role']], Heading="Welcome " + kwargs['first_name'],
                           data=kwargs)


@app.route("/EditRequest/<int:request_id>", methods=['GET', 'POST'])
@app.route("/NewRequest", methods=['GET', 'POST'])
@permission_required({"Student"})
def submit_application(request_id=None, **kwargs):
    unit_choices = [(unit.key.id(), unit.unit_name) for unit in
                    Unit.query(Unit.is_Active == True, Unit.faculty_key == kwargs['faculty']).fetch(
                        projection=[Unit.unit_name])]
    form = SubmissionForm()
    form.unit.choices = unit_choices

    if request.method == 'POST' and request_id:
        data = Requests.get_by_id(request_id)
        data.unit = Unit.get_by_id(int(form.unit.data)).key
        data.assignment_exam_name = form.assignment_exam_name.data
        data.description = form.description.data
        data.update_date = datetime.now()
        data.status = "Waiting for Tutor"
        if get_blobkey("evidence_image"):
            data.evidence_image = get_blobkey("evidence_image")

        if get_blobkey("evidence_document"):
            data.evidence_document = get_blobkey("evidence_document")
        data.put()
        trello_resp = upsert_trello_card(data, data.trello_id)

        notify_tutors("Update", request_id, data)
        flash('Request Updated!', 'success')
        return redirect(url_for('submit_application', request_id=request_id))
    elif request.method == 'POST':
        data = Requests(
            faculty=kwargs['faculty'],
            unit=Unit.get_by_id(int(form.unit.data)).key,
            assignment_exam_name=form.assignment_exam_name.data,
            description=form.description.data,
            university_email=session.get('UserID'),
            student_number=kwargs['student_id'],
            evidence_image=get_blobkey("evidence_image"),
            evidence_document=get_blobkey("evidence_document"),
            create_date=datetime.now(),
            update_date=datetime.now(),
            status="Waiting for Tutor"
        )

        trello_resp = upsert_trello_card(data, None)
        data.trello_id = trello_resp['id']
        data.put()
        update_trello_id(data)
        notify_tutors("New", data.key.id(), data)
        flash('Request submitted!', 'success')
        return redirect(url_for('submit_application', request_id=data.key.id()))

    upload_url = blobstore.create_upload_url(url_for('submit_application'))
    if request_id:
        old_data = Requests.get_by_id(request_id)
        if old_data.university_email == session['UserID']:
            upload_url = blobstore.create_upload_url(url_for('submit_application', request_id=request_id))
            form.unit.data = str(old_data.unit.id())
            form.assignment_exam_name.data = old_data.assignment_exam_name
            form.description.data = old_data.description
            form.evidence_document.data = old_data.evidence_document
            form.evidence_image.data = old_data.evidence_image
            form.status.data = old_data.status
            form.tutor_comments.data = old_data.tutor_comments
            form.extended_to.data = old_data.extended_to
        else:
            flash('You don\'t have the permissions to edit this record!', 'danger')
            return redirect(url_for('submit_application'))

    return render_template('html/Dashboard/Student/SubmitNew.html', uploadUri=upload_url, Heading="Your Circumstances",
                           navigation_bar=nav_bar[kwargs['user_role']], form=form, request_id=request_id,
                           data=kwargs)


@app.route('/Chat/<int:request_id>', methods=['GET', 'POST'])
@permission_required({"Student", "Tutor"})
def chat(request_id=0, **kwargs):
    if request_id:
        request_data = Requests.get_by_id(request_id)
        if request_data:
            if ((kwargs['user_role'] == "Student" and not request_data.university_email == session['UserID']) or
                    kwargs['user_role'] == "Tutor" and not request_data.faculty == kwargs['faculty']):
                flash('You don\'t have the permissions to view this record!', 'danger')
                return redirect(url_for('my_dashboard'))
        else:
            flash('You don\'t have the permissions to view this record!', 'danger')
            return redirect(url_for('my_dashboard'))

    old_messages = Chat.query(Chat.request == request_data.key).order(
        Chat.message_time).fetch()

    return render_template('html/Dashboard/Chat.html', request_id=request_id, old_messages=old_messages, data=kwargs,
                           Heading="Live Chat: " + request_data.assignment_exam_name,
                           navigation_bar=nav_bar[kwargs['user_role']])


@app.route("/Settings", methods=['GET', 'POST'])
@permission_required({"Student", "Tutor"})
def settings(**kwargs):
    form = SettingsForm()
    user_data = login(session.get('UserID'))
    google_oauth = oAuthLogins.query(oAuthLogins.user_key == user_data.key).count()
    oauth_status = True if google_oauth == 1 else False

    if request.method == 'POST':
        if kwargs['user_role'] == "Student":
            graduation_date = datetime.strptime(str(form.graduation_date.data), '%Y-%m-%d')

        mobile_check = UserDetails.query(UserDetails.ContactDetails.mobile_number == form.mobile_number.data,
                                         UserDetails.AccountDetails.university_email != session.get('UserID')).get()
        if mobile_check:
            flash('Mobile Number already in use!', 'danger')
            return redirect(url_for('settings'))
        elif not re.match("^07[0-9]{9}$", form.mobile_number.data):
            flash('Phone number is in wrong format. UK Numbers should start with 07 and be 11 characters long.',
                  'danger')
        elif kwargs['user_role'] == "Student" and graduation_date <= datetime.now():
            flash('Graduation date should be in the future!', 'danger')
            return redirect(url_for('settings'))
        else:
            user_data.ContactDetails.receive_email = form.receive_email.data
            user_data.ContactDetails.receive_text = form.receive_text.data
            user_data.ContactDetails.mobile_number = form.mobile_number.data
            if kwargs['user_role'] == "Student":
                user_data.PersonalDetails.graduation_date = graduation_date
            user_data.put()
            flash('Information Updated!', 'success')
    else:
        form.receive_email.data = user_data.ContactDetails.receive_email
        form.receive_text.data = user_data.ContactDetails.receive_text
        form.mobile_number.data = user_data.ContactDetails.mobile_number
        if kwargs['user_role'] == "Student":
            form.graduation_date.data = user_data.PersonalDetails.graduation_date

    return render_template('html/Dashboard/Settings.html', data=kwargs,
                           navigation_bar=nav_bar[kwargs['user_role']],
                           Heading="Account Settings: " + session.get('UserID'),
                           oauth_status=oauth_status, form=form)


############################################################
# Tutor Only VIEWS

@app.route("/CheckRequest/<int:request_id>", methods=['GET', 'POST'])
@permission_required({"Tutor"})
def check_request(request_id=None, **kwargs):
    unit_choices = [(unit.key.id(), unit.unit_name) for unit in
                    Unit.query(Unit.is_Active == True, Unit.faculty_key == kwargs['faculty']).fetch(
                        projection=[Unit.unit_name])]
    form = SubmissionForm()
    form.unit.choices = unit_choices
    old_data = Requests.get_by_id(request_id)

    if old_data:
        if old_data.faculty == kwargs['faculty']:
            if request.method == 'POST' and request_id:
                if old_data.status != form.status.data:
                    move_card(old_data.trello_id, form.status.data, form.extended_to.data)
                    notify_user(old_data.university_email, old_data, old_data.status, form.status.data)
                old_data.status = form.status.data
                old_data.tutor_comments = form.tutor_comments.data
                old_data.update_date = datetime.now()

                if form.status.data == "Approved" and not form.extended_to.data:
                    flash('Please enter a new extension date if you have approved!', 'danger')
                    return redirect(url_for('check_request', request_id=request_id))

                if form.status.data == "Approved" and form.extended_to.data:
                    extended_date = datetime.strptime(str(form.extended_to.data), '%Y-%m-%d')
                    if extended_date <= datetime.now():
                        flash('Extension date should be in the future!', 'danger')
                        return redirect(url_for('check_request', request_id=request_id))
                    else:
                        old_data.extended_to = extended_date

                old_data.put()
                flash('Request Updated!', 'success')
                return redirect(url_for('check_request', request_id=request_id))

            if old_data.status == "Approved" or old_data.status == "Rejected":
                flash("This request can not be edited since it has already been processed.", "info")

            form.student_id.data = old_data.student_number
            form.unit.data = str(old_data.unit.id())
            form.assignment_exam_name.data = old_data.assignment_exam_name
            form.description.data = old_data.description
            form.evidence_document.data = old_data.evidence_document
            form.evidence_image.data = old_data.evidence_image
            form.status.data = old_data.status
            form.tutor_comments.data = old_data.tutor_comments
            form.extended_to.data = old_data.extended_to
        else:
            flash('You don\'t have the permissions to view this record!', 'danger')
            return redirect(url_for('my_dashboard'))
    else:
        flash('Record does not exist!', 'danger')
        return redirect(url_for('my_dashboard'))

    return render_template('html/Dashboard/Tutor/CheckRequest.html', Heading="Request ID: " + str(request_id),
                           navigation_bar=nav_bar[kwargs['user_role']], data=kwargs, form=form, request_id=request_id)


############################################################
# Admin Only VIEWS

@app.route("/Faculties", methods=['GET', 'POST'])
@permission_required({"Admin"})
def faculties(**kwargs):
    if not Faculty.query().fetch():
        flash("No faculties created yet!", "warning")
    faculty_data = Faculty.query().fetch()

    faculty_data_list = [faculty._to_dict() for faculty in faculty_data]

    index = 0
    for faculty in faculty_data_list:
        faculty_extra_data = (
            {
                "tutor_amount": UserDetails.query(
                    UserDetails.AccountDetails.faculty == faculty_data[index].key,
                    UserDetails.AccountDetails.is_tutor == True).count(),
                "unit_amount": Unit.query(Unit.faculty_key == faculty_data[index].key).count(),
                "id": faculty_data[index].key.id()
            })
        faculty.update(faculty_extra_data)
        index += 1

    return render_template("html/Dashboard/Admin/Faculties.html", Heading="Your Faculties",
                           data=kwargs, navigation_bar=nav_bar[kwargs['user_role']],
                           faculty=faculty_data_list)


@app.route("/Faculties/Edit/<int:request_id>", methods=['GET', 'POST'])
@app.route("/Faculties/Add/", methods=['GET', 'POST'])
@permission_required({"Admin"})
def faculty_config(request_id=None, **kwargs):
    form = FacultyForm()
    entity = None
    next_page = None
    if request.method == 'POST' and request_id:
        entity = Faculty.get_by_id(request_id)
        flash('Faculty updated', 'success')
        next_page = redirect(url_for('faculty_config', request_id=request_id))
    elif request.method == 'POST':
        entity = Faculty()
        flash('Faculty added', 'success')
        next_page = redirect(url_for('faculty_config'))

    if entity:
        entity.faculty_name = form.faculty_name.data
        entity.is_Active = form.is_Active.data
        entity.put()
        return next_page

    if request_id:
        entity = Faculty.get_by_id(request_id)
        form.faculty_name.data = entity.faculty_name
        form.is_Active.data = entity.is_Active

    return render_template("html/Dashboard/Admin/FacultyConfig.html", form=form, Heading="Faculty Configuration",
                           data=kwargs, navigation_bar=nav_bar[kwargs['user_role']])


@app.route("/Units", methods=['GET', 'POST'])
@permission_required({"Admin"})
def units(**kwargs):
    if not Unit.query().fetch():
        flash("No Units created yet!", "warning")
    unit_data = Unit.query().fetch()
    unit_data_list = [unit._to_dict() for unit in unit_data]

    index = 0
    for unit in unit_data_list:
        unit_extra_data = (
            {
                "tutor_amount": UserDetails.query(
                    UserDetails.AccountDetails.unit_tutor == unit_data[index].key).count(),
                "faculty": Faculty.get_by_id(unit_data[index].faculty_key.id()),
                "id": unit_data[index].key.id()
            })
        unit.update(unit_extra_data)
        index += 1

    return render_template("html/Dashboard/Admin/Units.html", Heading="Your Units",
                           data=kwargs, navigation_bar=nav_bar[kwargs['user_role']],
                           unit=unit_data_list)


@app.route("/Units/Edit/<int:request_id>", methods=['GET', 'POST'])
@app.route("/Units/Add/", methods=['GET', 'POST'])
@permission_required({"Admin"})
def unit_config(request_id=None, **kwargs):
    faculty_choices = [(faculty.key.id(), faculty.faculty_name) for faculty in
                       Faculty.query(Faculty.is_Active == True).fetch(projection=[Faculty.faculty_name])]
    form = UnitForm()
    form.faculty_key.choices = faculty_choices
    entity = None
    next_page = None
    if request.method == 'POST' and request_id:
        entity = Unit.get_by_id(request_id)
        flash('Unit updated', 'success')
        next_page = redirect(url_for('unit_config', request_id=request_id))
    elif request.method == 'POST':
        entity = Unit()
        flash('Unit added', 'success')
        next_page = redirect(url_for('unit_config'))

    if entity:
        entity.unit_name = form.unit_name.data
        entity.is_Active = form.is_Active.data
        entity.faculty_key = Faculty.get_by_id(int(form.faculty_key.data)).key
        entity.put()
        return next_page
    if request_id:
        entity = Unit.get_by_id(request_id)
        form.faculty_key.data = str(entity.faculty_key.id())
        form.unit_name.data = entity.unit_name
        form.is_Active.data = entity.is_Active

    return render_template("html/Dashboard/Admin/UnitConfig.html", form=form, Heading="Unit Configuration",
                           data=kwargs, navigation_bar=nav_bar[kwargs['user_role']])


@app.route("/Tutors", methods=['GET', 'POST'])
@permission_required({"Admin"})
def tutors(**kwargs):
    if not UserDetails.query(UserDetails.AccountDetails.is_tutor == True).fetch():
        flash("Error occurred when retrieving Tutors list or no tutors added yet.", "warning")
    tutors_data = UserDetails.query(UserDetails.AccountDetails.is_tutor == True).fetch()
    tutors_data_list = [tutor._to_dict() for tutor in tutors_data]

    index = 0
    for tutor in tutors_data_list:
        if tutors_data[index].AccountDetails.unit_tutor:
            unit = Unit.get_by_id(tutors_data[index].AccountDetails.unit_tutor.id()).unit_name
        else:
            unit = "Unset"
        tutors_extra_data = (
            {
                'unit': unit,
                'faculty': Faculty.get_by_id(tutors_data[index].AccountDetails.faculty.id()),
                'id': tutors_data[index].key.id()
            }
        )
        tutor.update(tutors_extra_data)
        index += 1

    return render_template("html/Dashboard/Admin/Tutors.html", Heading="Your Tutors",
                           data=kwargs, navigation_bar=nav_bar[kwargs['user_role']],
                           users=tutors_data_list)


@app.route("/Tutor/Add/", methods=['GET', 'POST'])
@permission_required({"Admin"})
def add_tutor(**kwargs):
    form = TutorRegisForm()
    faculty_choices = [(faculty.key.id(), faculty.faculty_name) for faculty in
                       Faculty.query(Faculty.is_Active == True).fetch(projection=[Faculty.faculty_name])]
    unit_choices = [(unit.key.id(), unit.unit_name) for unit in
                    Unit.query(Unit.is_Active == True).fetch(projection=[Unit.unit_name])]
    form.faculty_key.choices = faculty_choices
    form.unit_key.choices = unit_choices
    if request.method == 'POST':
        if form.validate_on_submit():
            first_name = form.first_name.data
            last_name = form.last_name.data
            email = (form.email.data).lower()
            password = form.password.data
            unit = form.unit_key.data
            faculty = form.faculty_key.data
            mobile_number = form.mobile_number.data
            email_check = UserDetails.query(UserDetails.AccountDetails.university_email == email).get()
            mobile_check = UserDetails.query(UserDetails.ContactDetails.mobile_number == mobile_number).get()

            # Check if user exists already
            if email_check:
                flash('Email already in use!.', 'danger')
            elif mobile_check:
                flash('Mobile Number already in use!', 'danger')
            elif not re.match("^07[0-9]{9}$", mobile_number):
                flash('Phone number is in wrong format. UK Numbers should start with 07 and be 11 characters long.',
                      'danger')
            else:
                hash_code = uuid.uuid4().hex
                registration_data = UserDetails(
                    PersonalDetails=Personal_Details(first_name=first_name, last_name=last_name),
                    AccountDetails=Account_Details(verification_hash=hash_code, university_email=email.lower(),
                                                   password=hash_me(password), faculty=Faculty.get_by_id(faculty).key,
                                                   unit_tutor=Unit.get_by_id(unit).key,
                                                   verified_status=False, is_tutor=True, is_admin=False,
                                                   is_active=False),
                    ContactDetails=Contact_Details(mobile_number=mobile_number, receive_email=True)
                )
                registration_data.put()
                # Send Verification Email
                send_verification_email(email, hash_code)
                flash("Tutor added, please get them to verify their email.", "success")
                return redirect(url_for("tutors"))

    return render_template("html/Dashboard/Admin/AddTutor.html", form=form,
                           Heading="Add New Tutor",
                           data=kwargs, navigation_bar=nav_bar[kwargs['user_role']])


@app.route("/Tutor/Edit/<int:request_id>", methods=['GET', 'POST'])
@permission_required({"Admin"})
def tutor_config(request_id=None, **kwargs):
    form = TutorForm()
    entity = None
    next_page = None

    faculty_choices = [(faculty.key.id(), faculty.faculty_name) for faculty in
                       Faculty.query(Faculty.is_Active == True).fetch(projection=[Faculty.faculty_name])]
    unit_choices = [(unit.key.id(), unit.unit_name) for unit in
                    Unit.query(Unit.is_Active == True).fetch(projection=[Unit.unit_name])]
    form.faculty_key.choices = faculty_choices
    form.unit_key.choices = unit_choices

    if request.method == 'POST' and request_id:
        entity = UserDetails.get_by_id(request_id)
        flash('Tutor updated', 'success')
        next_page = redirect(url_for('tutor_config', request_id=request_id))

    if entity:
        entity.AccountDetails.faculty = Faculty.get_by_id(int(form.faculty_key.data)).key
        entity.AccountDetails.unit_tutor = Unit.get_by_id(int(form.unit_key.data)).key
        entity.AccountDetails.is_tutor = form.is_Tutor.data
        if not form.is_Tutor.data:
            del entity.AccountDetails.unit_tutor
        entity.put()
        return next_page

    if request_id:
        entity = UserDetails.get_by_id(request_id)
        form.faculty_key.data = str(entity.AccountDetails.faculty.id())
        if entity.AccountDetails.is_tutor and entity.AccountDetails.unit_tutor:
            form.unit_key.data = str(entity.AccountDetails.unit_tutor.id())
        form.is_Tutor.data = entity.AccountDetails.is_tutor

    return render_template("html/Dashboard/Admin/TutorsConfig.html", form=form,
                           Heading="Tutor Configuration: " + entity.AccountDetails.university_email,
                           data=kwargs, navigation_bar=nav_bar[kwargs['user_role']])


@app.route("/Users", methods=['GET', 'POST'])
@permission_required({"Admin"})
def users(**kwargs):
    if not UserDetails.query().fetch():
        flash("Error occurred when retrieving users list", "danger")
    users_data = UserDetails.query().fetch()
    users_data_list = [user._to_dict() for user in users_data]

    index = 0
    for user in users_data_list:
        users_extra_data = (
            {
                'faculty': Faculty.get_by_id(users_data[index].AccountDetails.faculty.id()),
                'id': users_data[index].key.id()
            }
        )
        user.update(users_extra_data)
        index += 1

    return render_template("html/Dashboard/Admin/Users.html", Heading="Your Users",
                           data=kwargs, navigation_bar=nav_bar[kwargs['user_role']],
                           users=users_data_list)


@app.route("/Users/Edit/<int:request_id>", methods=['GET', 'POST'])
@permission_required({"Admin"})
def users_config(request_id=None, **kwargs):
    faculty_choices = [(faculty.key.id(), faculty.faculty_name) for faculty in
                       Faculty.query().fetch(projection=[Faculty.faculty_name])]

    form = UserForm()
    form.faculty_key.choices = faculty_choices

    if request.method == 'POST' and request_id:
        entity = UserDetails.get_by_id(request_id)
        next_page = redirect(url_for('users_config', request_id=request_id))
        entity.AccountDetails.university_email = form.university_email.data
        entity.AccountDetails.faculty = Faculty.get_by_id(int(form.faculty_key.data)).key
        entity.AccountDetails.is_active = form.is_Active.data
        entity.AccountDetails.is_admin = form.is_Admin.data
        entity.AccountDetails.is_tutor = form.is_Tutor.data
        if form.is_Tutor.data:
            entity.AccountDetails.is_tutor = True
            entity.AccountDetails.is_admin = False

        if form.is_Admin.data:
            entity.AccountDetails.is_admin = True
            entity.AccountDetails.is_tutor = False
            del entity.AccountDetails.unit_tutor

        admin_check = UserDetails.query(UserDetails.AccountDetails.is_admin == True,
                                        UserDetails.AccountDetails.is_active == True)
        if not form.is_Admin.data and admin_check.count() == 1:
            admin_data = admin_check.get()
            if admin_data.AccountDetails.university_email == form.university_email.data:
                flash("Can not downgrade the last active admin on the system.", "danger")
                return next_page

        flash('User updated', 'success')
        entity.put()
        return next_page

    if request_id:
        entity = UserDetails.get_by_id(request_id)
        form.university_email.data = entity.AccountDetails.university_email
        form.faculty_key.data = str(entity.AccountDetails.faculty.id())
        form.is_Active.data = entity.AccountDetails.is_active
        form.is_Admin.data = entity.AccountDetails.is_admin
        form.is_Tutor.data = entity.AccountDetails.is_tutor

    return render_template("html/Dashboard/Admin/UsersConfig.html", form=form, Heading="User Configuration",
                           data=kwargs, navigation_bar=nav_bar[kwargs['user_role']])


############################################################
# AJAX Only VIEWS
# Send Password Reset Email:
@app.route('/Ajax/ResetPassword', methods=['POST'])
def reset_password_email():
    email = request.form.get('reset_email')
    if login(email):
        # Check if old reset information is valid
        old_pass_data = PasswordReset.query(PasswordReset.university_email == email.lower()).get()
        if old_pass_data and datetime.now() < old_pass_data.code_expiry:
            # STILL Valid:
            hash_code = old_pass_data.verification_hash
        else:
            # No longer valid so delete
            if old_pass_data:
                old_pass_data.key.delete()
            # Create new
            hash_code = uuid.uuid4().hex
            reset_data = PasswordReset(
                university_email=email.lower(),
                verification_hash=hash_code,
                code_expiry=datetime.now() + timedelta(days=1)
            )
            reset_data.put()
        RESET_URL = (
                request.url_root + url_for('reset_password').replace("/", "") +
                "?email=" + email +
                "&code=" + hash_code
        )
        mail.send_mail(
            sender="support@mc-system-223313.appspotmail.com",
            to=email,
            subject="MitiCirc - Reset Password Link",
            body="",
            html=render_template('email/password_reset.html', EMAIL_HEADER="Password Reset Request Received!",
                                 RESET_URL=RESET_URL)

        )

    return ""


@app.route('/Ajax/GetUnit', methods=['POST'])
def get_units():
    faculty = int(request.form.get('faculty'))

    possible_units = [(unit.key.id(), unit.unit_name) for unit in
                      Unit.query(Unit.faculty_key == Faculty.get_by_id(faculty).key, Unit.is_Active == True).fetch()]
    return jsonify(possible_units)


@app.route('/Ajax/DeleteAttachment', methods=['POST'])
def delete_attachment():
    attachment = blobstore.get(request.form.get("id"))
    attachment_type = request.form.get("type")
    if attachment and attachment_type:
        if attachment_type == "image":
            user_request = Requests.query(Requests.evidence_image == blobstore.BlobKey(request.form.get("id"))).get()
            user_request.evidence_image = None
        if attachment_type == "document":
            user_request = Requests.query(Requests.evidence_document == blobstore.BlobKey(request.form.get("id"))).get()
            user_request.evidence_document = None
        user_request.put()
        attachment.delete()
        delete_trello_attachment(user_request.trello_id, request.form.get("id"))
        return "True"
    return "false"


############################################################
# CRON Only VIEWS

@app.route('/CRON/Clear/FailedLogins', methods=['GET', 'POST'])
def failed_logins():
    failed = FailedLogins.query(FailedLogins.timestamp < datetime.now() - timedelta(minutes=15))
    if failed.count() > 0:
        ndb.delete_multi(
            failed.fetch(keys_only=True)
        )
    return jsonify({"Deleted": failed.count()})


@app.route('/CRON/Clear/ExpiredPasswordResets', methods=['GET', 'POST'])
def expired_password_resets():
    expired = PasswordReset.query(PasswordReset.code_expiry < datetime.now())
    if expired.count() > 0:
        ndb.delete_multi(expired.fetch(keys_only=True))
    return jsonify({"Deleted": expired.count()})


@app.route('/CRON/Disable/Accounts', methods=['GET', 'POST'])
def disable_accounts():
    inactive_accounts = UserDetails.query(UserDetails.PersonalDetails.graduation_date < datetime.now(),
                                          UserDetails.AccountDetails.is_admin == False,
                                          UserDetails.AccountDetails.is_tutor == False,
                                          UserDetails.AccountDetails.is_active == True)
    if inactive_accounts.count() > 0:
        for user in inactive_accounts.fetch():
            user.AccountDetails.is_active = False
        ndb.put_multi(inactive_accounts)
    return jsonify({"Disabled": inactive_accounts.count()})


############################################################
# PUSHER API
@app.route('/Ajax/Message', methods=['POST'])
def message():
    try:
        username = request.form.get('username')
        message = base64.b64encode(request.form.get('message').decode('utf-8'))
        request_id = request.form.get('request_id')
        timenow = datetime.now()
        email = request.form.get('email')

        Chat(
            request=Requests.get_by_id(int(request_id)).key,
            username=username,
            message=message,
            message_time=timenow,
            email=email
        ).put()

        params = {
            "data": "{\"email\":\"" + email + "\",\"message\":\"" + message + "\",\"username\":\"" + username + "\",\"message_time\":\"" + timenow.strftime(
                '%H:%M | %d-%m-%Y') + "\"}", "name": "new-message", "channel": request_id + "-channel"}
        pusher(params)
        return jsonify({'result': 'success'})
    except:
        return jsonify({'result': 'failure'})


def pusher_get_sign(timestamp, md5):
    app_id = "your id here"
    key = "your key here"
    secret = "your secret here"
    string = "POST\n/apps/" + app_id + "/events\nauth_key=" + key + "&auth_timestamp=" + timestamp + "&auth_version=1.0&body_md5=" + md5
    return hmac.new(secret, string, hashlib.sha256).hexdigest()


def pusher(params):
    payload = json.dumps(params)
    body_md5 = hashlib.md5(payload).hexdigest()
    auth_timestamp = '%.0f' % time.time()
    auth_signature = pusher_get_sign(auth_timestamp, body_md5)
    url_endpoint = ("https://api-eu.pusher.com/apps/Your ID here/events?" +
                    "body_md5=" + body_md5 + "&" +
                    "auth_version=1.0&" +
                    "auth_key=your key here&" +
                    "auth_timestamp=" + auth_timestamp + "&" +
                    "auth_signature=" + auth_signature)

    resp = urlfetch.fetch(
        url=url_endpoint,
        method="POST",
        payload=payload,
        headers={"Content-Type": "application/json"}
    )
    return resp.content


############################################################
# TRELLO Only VIEWS

@app.route('/Webhook/TrelloUpdate', methods=['POST', 'HEAD'])
def trello_update():
    if not request.headers['x-trello-webhook']:
        return jsonify({"action": "failed"})

    from_trello = base64.b64encode(
        hmac.new(TRELLO_DATA.get("OAUTH_KEY"), request.data + TRELLO_DATA.get("CALL_BACK"), hashlib.sha1).digest())

    if not from_trello == request.headers['x-trello-webhook']:
        return jsonify({"action": "failed"})

    JSON_DATA = json.loads(request.data)
    # Only trigger if it's a card movement
    if not JSON_DATA["action"]["display"]['translationKey'] == "action_move_card_from_list_to_list":
        return jsonify({"action": "failed"})
    trello_id = JSON_DATA["action"]["data"]["card"]["id"]

    # Get the new app
    list_id = JSON_DATA["action"]["data"]["card"]["idList"]

    student_request = Requests.query(Requests.trello_id == trello_id).get()

    new_status = None
    if list_id == TRELLO_DATA.get("CARDS").get("ON_STUDENT"):
        new_status = "Waiting for Student"
    elif list_id == TRELLO_DATA.get("CARDS").get("ON_TUTOR"):
        new_status = "Waiting for Tutor"
    elif list_id == TRELLO_DATA.get("CARDS").get("APPROVED"):
        new_status = "Approved"
        url_endpoint = ("https://api.trello.com/1/cards/" + trello_id + "?customFieldItems=true&key=" + TRELLO_DATA.get(
            "API_KEY") + "&token=" + TRELLO_DATA.get("TOKEN"))
        resp = urlfetch.fetch(
            url=url_endpoint,
            method="GET",
            headers={"Content-Type": "application/json"}
        )
        customFieldItems = json.loads(resp.content)['customFieldItems']
        for item in customFieldItems:
            if item['idCustomField'] == TRELLO_DATA.get("CUSTOM").get("ExtensionDate"):
                student_request.extended_to = datetime.strptime(item['value']['date'], "%Y-%m-%dT%H:%M:%S.%fZ")

    elif list_id == TRELLO_DATA.get("CARDS").get("REJECTED"):
        new_status = "Rejected"

    student_request.status = new_status
    student_request.put()

    return jsonify({"action": "successful"})


def move_card(trello_id, new_status, date):
    if new_status == "Waiting for Student":
        idList = TRELLO_DATA.get("CARDS").get("ON_STUDENT");
    elif new_status == "Waiting for Tutor":
        idList = TRELLO_DATA.get("CARDS").get("ON_TUTOR");
    elif new_status == "Approved":
        idList = TRELLO_DATA.get("CARDS").get("APPROVED");
    elif new_status == "Rejected":
        idList = TRELLO_DATA.get("CARDS").get("REJECTED");

    params = {
        "idList": idList,
        "key": TRELLO_DATA.get("API_KEY"),
        "token": TRELLO_DATA.get("TOKEN")
    }

    payload = json.dumps(params)
    url_endpoint = "https://api.trello.com/1/cards/" + trello_id
    resp = urlfetch.fetch(
        url=url_endpoint,
        method="PUT",
        payload=payload,
        headers={"Content-Type": "application/json"}
    )

    if new_status == "Approved":
        url_endpoint = ("https://api.trello.com/1/cards/" + trello_id + "/customField/" + TRELLO_DATA.get("CUSTOM").get(
            "ExtensionDate") + "/item")
        params = {
            "value": {"date": date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")},
            "key": TRELLO_DATA.get("API_KEY"),
            "token": TRELLO_DATA.get("TOKEN")
        }
        payload = json.dumps(params)
        resp = urlfetch.fetch(
            url=url_endpoint,
            method="PUT",
            payload=payload,
            headers={"Content-Type": "application/json"}
        )

    return resp


def update_trello_id(data):
    params = {
        "value": {"text": str(data.key.id())},
        "key": TRELLO_DATA.get("API_KEY"),
        "token": TRELLO_DATA.get("TOKEN")
    }

    url_endpoint = ("https://api.trello.com/1/cards/" + data.trello_id + "/customField/" + TRELLO_DATA.get(
        "CUSTOM").get("RequestID") + "/item")
    payload = json.dumps(params)

    resp = urlfetch.fetch(
        url=url_endpoint,
        method="PUT",
        payload=payload,
        headers={"Content-Type": "application/json"}
    )

    return None


def upsert_trello_card(data, trello_id):
    if trello_id:
        method = "PUT"
        url_endpoint = ("https://api.trello.com/1/cards/" + trello_id)
    else:
        method = "POST"
        url_endpoint = ("https://api.trello.com/1/cards?")

    params = {
        "name": data.student_number + " - " + data.unit_name(),
        "idList": TRELLO_DATA.get("CARDS").get("ON_TUTOR"),
        "due": "null",
        "desc": "Faculty: " + data.faculty_name() + "\nAssignment/Exam Name: " + data.assignment_exam_name + "\nDescription: " + data.description,
        "key": TRELLO_DATA.get("API_KEY"),
        "token": TRELLO_DATA.get("TOKEN")
    }

    payload = json.dumps(params)

    card = json.loads(urlfetch.fetch(
        url=url_endpoint,
        method=method,
        payload=payload,
        headers={"Content-Type": "application/json"}
    ).content)

    attachments = get_attachments_trello(card['id'])
    attachments_list = []
    for item in json.loads(attachments):
        attachments_list.append(item['url'])

    url = request.url_root + url_for('serve').replace("/", "", 1) + "?id=" + str(data.evidence_document)

    if data.evidence_document and url not in attachments_list:
        params = {
            "id": card['id'],
            "url": url,
            "key": TRELLO_DATA.get("API_KEY"),
            "token": TRELLO_DATA.get("TOKEN"),
            "name": "Supporting Document"
        }

        payload = json.dumps(params)
        url_endpoint = ("https://api.trello.com/1/cards/" + card['id'] + "/attachments")

        attach = urlfetch.fetch(
            url=url_endpoint,
            method="POST",
            payload=payload,
            headers={"Content-Type": "application/json"}
        )

    url = request.url_root + url_for('serve').replace("/", "", 1) + "?id=" + str(data.evidence_image)

    if data.evidence_image and url not in attachments_list:
        params = {
            "id": card['id'],
            "url": url,
            "key": TRELLO_DATA.get("API_KEY"),
            "token": TRELLO_DATA.get("TOKEN"),
            "name": "Supporting Image"
        }

        payload = json.dumps(params)
        url_endpoint = ("https://api.trello.com/1/cards/" + card['id'] + "/attachments")

        attach = urlfetch.fetch(
            url=url_endpoint,
            method="POST",
            payload=payload,
            headers={"Content-Type": "application/json"}
        )

    return card


def get_attachments_trello(trello_id):
    url_endpoint = ("https://api.trello.com/1/cards/" + trello_id + "/attachments?&key=" + TRELLO_DATA.get(
        "API_KEY") + "&token=" + TRELLO_DATA.get("TOKEN"))

    attach = urlfetch.fetch(
        url=url_endpoint,
        method="GET",
        headers={"Content-Type": "application/json"}
    )
    return attach.content


def delete_trello_attachment(trello_id, attachment_endpoint):
    attach = get_attachments_trello(trello_id)

    for item in json.loads(attach):
        if item['url'] == request.url_root + url_for('serve').replace("/", "", 1) + "?id=" + str(attachment_endpoint):
            attachment_id = item['id']
            url_endpoint = (
                    "https://api.trello.com/1/cards/" + trello_id + "/attachments/" + attachment_id + "?&key=" + TRELLO_DATA.get(
                "API_KEY") + "&token=" + TRELLO_DATA.get("TOKEN"))
            attach = urlfetch.fetch(
                url=url_endpoint,
                method="DELETE",
                headers={"Content-Type": "application/json"}
            )

    return None


############################################################
# BLOBSTORE API

def get_blobkey(file_name):
    if request.files.get(file_name, ):
        f = request.files[file_name]
        header = f.headers['Content-Type']
        parsed_header = http.parse_options_header(header)
        blob_key = blobstore.BlobKey(parsed_header[1]['blob-key'])
        return blob_key
    return None


@app.route("/Serve", methods=['GET', 'POST'])
def serve():
    if session.get('Logged_In', False):
        blob_info = blobstore.get(request.args.get("id"))
        content = BytesIO(blob_info.open().read())
        return send_file(content, attachment_filename=blob_info.filename, as_attachment=True)
    abort(404)


############################################################
# FUNCTIONS
def api_launcher(method, url_endpoint, params):
    if method == "GET":
        p = urllib.urlencode(params) if params else ""
        resp = urlfetch.fetch(
            url_endpoint + "?" + p
        )
    if method == "POST":
        resp = urlfetch.fetch(
            url=url_endpoint,
            method="POST",
            payload=urllib.urlencode(params)
        )
    if method == "oAuthv2":
        p = urllib.urlencode(params) if params else ""
        resp = urlfetch.fetch(
            url=url_endpoint,
            method="POST",
            payload=p,
        )

    return json.loads(resp.content)


def oauth_launcher(method, url_endpoint, params, token):
    if method == "GET":
        p = urllib.urlencode(params) if params else ""
        resp = urlfetch.fetch(
            url_endpoint + "?" + p,
            headers={"Authorization": "Bearer " + token}
        )
    if method == "POST":
        resp = urlfetch.fetch(
            url=url_endpoint,
            method="POST",
            payload=urllib.urlencode(params),
            headers={"Authorization": "Bearer " + token}
        )
    return json.loads(resp.content)


# Validate Login
def check_login(email, password):
    if FailedLogins.query(FailedLogins.ip_address == request.remote_addr).count() >= MAX_LOGIN_ATTEMPTS:
        flash("IP has been temporarily blocked.", "danger")
        return False
    if FailedLogins.query(FailedLogins.attempted_email == email).count() >= MAX_LOGIN_ATTEMPTS:
        flash("User has been temporarily blocked.", "danger")
        return False

    q = UserDetails.query(
        UserDetails.AccountDetails.university_email == email
    )

    if q.count() == 1:
        user = login(email)
        if check_hashed_string(user.AccountDetails.password, password):
            if not user.AccountDetails.verified_status:
                flash('Please check your email to verify your account before use.', 'danger')
                return False
            # Mark user as logged in
            session['Logged_In'] = True
            session['UserID'] = user.AccountDetails.university_email.lower()
            ndb.delete_multi(
                FailedLogins.query(ndb.OR(FailedLogins.attempted_email == email,
                                          FailedLogins.ip_address == request.remote_addr)).fetch(keys_only=True)
            )
            return True

    FailedLogins(attempted_email=email, ip_address=request.remote_addr, timestamp=datetime.now()).put()
    ip_count = MAX_LOGIN_ATTEMPTS - 1 - FailedLogins.query(FailedLogins.ip_address == request.remote_addr).count()
    email_count = MAX_LOGIN_ATTEMPTS - 1 - FailedLogins.query(FailedLogins.attempted_email == email).count()
    current_count = ip_count if ip_count < email_count else email_count
    flash('Email or Password incorrect, please try again. You have ' + str(current_count) + ' attempts remaining.',
          'danger')
    return False


# Register
def register(first_name, last_name, student_number, graduation_date, mobile_number, university_email,
             password, faculty):
    email_check = UserDetails.query(UserDetails.AccountDetails.university_email == university_email.lower()).get()
    mobile_check = UserDetails.query(UserDetails.ContactDetails.mobile_number == mobile_number).get()
    student_check = UserDetails.query(UserDetails.PersonalDetails.student_number == student_number).get()

    # Check if user exists already
    if student_check:
        flash('Student already signed up! Not you? Contact an admin.', 'danger')
        return False
    if not re.match("^i[0-9]+$", student_number):
        print student_number
        flash('Student Number should be in the following format: i7469693', 'danger')
        return False

    if mobile_check:
        flash('Mobile Number already in use!', 'danger')
        return False
    if not re.match("^07[0-9]{9}$", mobile_number):
        flash('Phone number is in wrong format. UK Numbers should start with 07 and be 11 characters long.', 'danger')
        return False

    if email_check:
        flash('Email Address already in use!', 'danger')
        return False
    if not re.compile("@bournemouth.ac.uk$").search(university_email):
        flash('Email address should end in @bournemouth.ac.uk!', 'danger')
        return False

    if graduation_date <= datetime.now():
        flash('Graduation date should be in the future!', 'danger')
        return False

    # Create the user
    hash_code = uuid.uuid4().hex
    registration_data = UserDetails(
        PersonalDetails=Personal_Details(first_name=first_name, last_name=last_name, student_number=student_number,
                                         graduation_date=graduation_date),
        AccountDetails=Account_Details(verification_hash=hash_code, university_email=university_email.lower(),
                                       password=hash_me(password), faculty=Faculty.get_by_id(faculty).key,
                                       verified_status=False, is_tutor=False, is_admin=False, is_active=False),
        ContactDetails=Contact_Details(mobile_number=mobile_number, receive_email=True)
    )
    registration_data.put()
    # Send Verification Email
    send_verification_email(university_email, hash_code)
    return registration_data


# Get User Information:
def login(email):
    return UserDetails.query(UserDetails.AccountDetails.university_email == email.lower()).get()


def hash_me(string):
    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + string.encode()).hexdigest() + ':' + salt


def check_hashed_string(hashed_string, entered_string):
    password, salt = hashed_string.split(':')
    return password == hashlib.sha256(salt.encode() + entered_string.encode()).hexdigest()


############################################################
# OTHER APIs

def notify_tutors(notification_type, request_id, data):
    tutor_list = UserDetails.query(
        UserDetails.AccountDetails.is_tutor == True,
        UserDetails.AccountDetails.is_active == True,
        UserDetails.AccountDetails.unit_tutor == data.unit,
        ndb.OR(UserDetails.ContactDetails.receive_text == True,
               UserDetails.ContactDetails.receive_email == True)
    ).fetch()
    for tutor in tutor_list:
        receive_text = tutor.ContactDetails.receive_text
        receive_email = tutor.ContactDetails.receive_email
        tutor_email = tutor.AccountDetails.university_email
        tutor_number = tutor.ContactDetails.mobile_number
        NAME = tutor.PersonalDetails.first_name
        user_data = login(data.university_email)
        STUDENT = user_data.PersonalDetails.student_number
        if notification_type == "New":
            subject = "A New Request Added by " + STUDENT + "!"
            template = "email/tutor_request_added.html"
            sms_string = " Hi " + NAME + ", a new request by " + STUDENT + " has been added. Please log in to check it."
        elif notification_type == "Updated":
            subject = "Request Updated by " + STUDENT + "!"
            template = "email/tutor_request_updated.html"
            sms_string = " Hi " + NAME + ", a request by " + STUDENT + " has been updated. Please log in to check it."
        if receive_email:
            URL = (request.url_root + url_for('check_request', request_id=request_id).replace("/", "", 1))

            mail.send_mail(
                sender="support@mc-system-223313.appspotmail.com",
                to=tutor_email,
                subject="MitiCirc - " + subject,
                body="",
                html=render_template(template, EMAIL_HEADER=subject, NAME=NAME, STUDENT=STUDENT, URL=URL)
            )
        if receive_text:
            send_sms(tutor_number, sms_string)

    return True


def notify_user(student_email, request_data, old_status, new_status):
    user_data = login(student_email)
    receive_email = user_data.ContactDetails.receive_email
    receive_text = user_data.ContactDetails.receive_text

    NAME = user_data.PersonalDetails.first_name
    DATA = request_data.assignment_exam_name

    if receive_email:
        URL = (request.url_root + url_for('submit_application', request_id=request_data.key.id()).replace("/", "", 1))
        mail.send_mail(
            sender="support@mc-system-223313.appspotmail.com",
            to=student_email,
            subject="MitiCirc - Your request for " + request_data.assignment_exam_name + " has been updated!",
            body="",
            html=render_template('email/request_updated.html', data=DATA, old_status=old_status, new_status=new_status,
                                 EMAIL_HEADER="Request Updated!",
                                 NAME=NAME, URL=URL)
        )
    if receive_text:
        send_sms(user_data.ContactDetails.mobile_number,
                 "Hi " + NAME + ", Your request for an extension for " + DATA + ", has been updated from " + old_status + " to " + new_status + "! Please log into the site to view the changes.")
    return True


# Verification Email
def send_verification_email(email, verification_hash):
    VERIFICATION_URL = (request.url_root + url_for('verify_email').replace("/", "") + "?email=" + email +
                        "&code=" + verification_hash)
    mail.send_mail(
        sender="support@mc-system-223313.appspotmail.com",
        to=email,
        subject="MitiCirc - verification code",
        body="",
        html=render_template('email/email_verification.html', EMAIL_HEADER="Thanks for signing up!",
                             VERIFICATION_URL=VERIFICATION_URL)
    )
    return None


def send_sms(to, body):
    params = {
        "To": to.replace("0", "+44", 1),
        "From": "MitiCirc",
        "Body": body
    }

    resp = urlfetch.fetch(
        url="https://api.twilio.com/2010-04-01/Accounts/" + TWILIO_SID + "/Messages.json",
        method="POST",
        payload=urllib.urlencode(params),
        headers={"Authorization": "Basic " + base64.b64encode(TWILIO_SID + ":" + TWILIO_TOKEN)}
    )
    return json.loads(resp.content)


def get_bg():
    background_url = memcache.get("background_image")
    if not background_url:
        background_url = api_launcher("GET", "https://api.unsplash.com/photos/random", {
            "client_id": "unsplash api key"})['urls']['regular']
        if not background_url:
            background_url = "https://images.unsplash.com/photo-1517334731427-caf8bed2ec8f?ixlib=rb-1.2.1&q=80&fm=jpg&crop=entropy&cs=tinysrgb&w=1080&fit=max&ixid=eyJhcHBfaWQiOjQ2OTgwfQ"
        memcache.set("background_image", background_url, time=180)
    return background_url


############################################################
# ERROR HANDLERS

@app.errorhandler(404)
def page_not_found(e):
    return e


@app.errorhandler(403)
def forbidden(e):
    return e


@app.errorhandler(401)
def unauthorised(e):
    flash('Please login to access this page', 'danger')
    return redirect(url_for('login_page'))

