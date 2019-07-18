from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, SelectField, TextAreaField, FileField, \
    BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, regexp


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class GoogleRegistrationForm(FlaskForm):
    student_number = StringField('iNumber')
    graduation_date = DateField('Graduation Date')
    faculty = SelectField('Faculty Name', coerce=int)
    mobile_number = StringField('Mobile Number')
    university_email = StringField('University Email', validators=[DataRequired()])
    submit = SubmitField('Register')

class SettingsForm(FlaskForm):
    receive_email = BooleanField('Receive Email Notifications?*')
    mobile_number = StringField('Mobile Number')
    receive_text = BooleanField('Receive Text Notifications?*')
    graduation_date = DateField('Graduation Date')
    submit = SubmitField('Update')


class RegistrationForm(FlaskForm):
    # Personal Data
    first_name = StringField('First Name')
    last_name = StringField('Last Name')
    student_number = StringField('iNumber')
    graduation_date = DateField('Graduation Date')
    faculty = SelectField('Faculty Name', coerce=int)

    # Contact Data
    mobile_number = StringField('Mobile Number')
    # Account Data
    university_email = StringField('University Email', validators=[DataRequired()])
    password = PasswordField('Password',
                             validators=[DataRequired(), EqualTo('confirm_password', message="Passwords Must Match")])
    confirm_password = PasswordField('Confirm Password')
    #
    submit = SubmitField('Register')

class TutorRegisForm(FlaskForm):
    # Personal Data
    first_name = StringField('First Name')
    last_name = StringField('Last Name')
    faculty_key = SelectField('Faculty Name', coerce=int)
    unit_key = SelectField('Unit Tutor of', coerce=int)

    # Contact Data
    mobile_number = StringField('Mobile Number')
    # Account Data
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password',
                             validators=[DataRequired(), EqualTo('confirm_password', message="Passwords Must Match")])
    confirm_password = PasswordField('Confirm Password')
    #
    submit = SubmitField('Register')



class PasswordResetForm(FlaskForm):
    password = PasswordField('Password',
                             validators=[DataRequired(), EqualTo('confirm_password', message="Passwords Must Match")])
    confirm_password = PasswordField('Confirm Password')
    submit = SubmitField('Change')


class SubmissionForm(FlaskForm):
    student_id = StringField('Student ID')
    unit = SelectField('Unit')
    assignment_exam_name = StringField('Assignment/Exam Title')
    evidence_document = FileField('Document')
    evidence_image = FileField('Image')
    description = TextAreaField('Description')
    status = SelectField("Status",
                         choices=[("Waiting for Student", "Waiting for Student"), ("Waiting for Tutor", "Waiting for Tutor"), ("Rejected", "Rejected"),
                                  ("Approved", "Approved")])
    tutor_comments = TextAreaField('Tutor Comments')
    extended_to = DateField('Extended To Date')

    submit = SubmitField('Submit')


class FacultyForm(FlaskForm):
    faculty_name = StringField('Faculty Name')
    is_Active = BooleanField('Is Active?')
    submit = SubmitField('Submit')


class UnitForm(FlaskForm):
    faculty_key = SelectField('Faculty Name')
    unit_name = StringField('Unit Name')
    is_Active = BooleanField('Is Active?')
    submit = SubmitField('Submit')


class UserForm(FlaskForm):
    university_email = StringField('University Email')
    faculty_key = SelectField('Faculty Name')
    is_Active = BooleanField('Is Active?')
    is_Admin = BooleanField('Is Admin?')
    is_Tutor = BooleanField('Is Tutor?')
    submit = SubmitField('Submit')


class TutorForm(FlaskForm):
    faculty_key = SelectField('Faculty Name')
    unit_key = SelectField('Unit Tutor of')
    is_Tutor = BooleanField('Is Tutor?')
    submit = SubmitField('Submit')
