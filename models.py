from google.appengine.ext import ndb


class oAuthLogins(ndb.Model):
    google_id = ndb.StringProperty()
    access_token = ndb.StringProperty()
    refresh_token = ndb.StringProperty()
    user_key = ndb.KeyProperty(kind='UserDetails')

# Basic Contact Details of the User
class Contact_Details(ndb.Model):
    mobile_number = ndb.StringProperty()
    receive_text = ndb.BooleanProperty()
    receive_email = ndb.BooleanProperty()

# Account Data
class Account_Details(ndb.Model):
    faculty = ndb.KeyProperty(kind='Faculty')
    unit_tutor = ndb.KeyProperty(kind='Unit')
    university_email = ndb.StringProperty()
    password = ndb.StringProperty()
    verified_status = ndb.BooleanProperty()
    verification_hash = ndb.StringProperty()
    is_tutor = ndb.BooleanProperty()
    is_admin = ndb.BooleanProperty()
    is_active = ndb.BooleanProperty()

# Basic Personal Information of the User
class Personal_Details(ndb.Model):
    first_name = ndb.StringProperty()
    last_name = ndb.StringProperty()
    graduation_date = ndb.DateProperty()
    student_number = ndb.StringProperty()
    image_avatar = ndb.BlobKeyProperty()

# Capture all this information as User information
class UserDetails(ndb.Model):
    PersonalDetails = ndb.StructuredProperty(Personal_Details)
    ContactDetails = ndb.StructuredProperty(Contact_Details)
    AccountDetails = ndb.StructuredProperty(Account_Details)


class PasswordReset(ndb.Model):
    university_email = ndb.StringProperty()
    verification_hash = ndb.StringProperty()
    code_expiry = ndb.DateTimeProperty()


class Requests(ndb.Model):
    university_email = ndb.StringProperty()
    student_number = ndb.StringProperty()
    status = ndb.StringProperty()
    tutor_comments = ndb.StringProperty()
    extended_to = ndb.DateProperty()

    faculty = ndb.KeyProperty(kind='Faculty')
    unit = ndb.KeyProperty(kind='Unit')
    assignment_exam_name = ndb.StringProperty()

    description = ndb.StringProperty()
    create_date = ndb.DateTimeProperty()
    update_date = ndb.DateTimeProperty()

    evidence_document = ndb.BlobKeyProperty()
    evidence_image = ndb.BlobKeyProperty()
    trello_id = ndb.StringProperty()
    def unit_name(self):
        unit_object = Unit.get_by_id(self.unit.id())
        return unit_object.unit_name
    def faculty_name(self):
        faculty_object = Faculty.get_by_id(self.faculty.id())
        return faculty_object.faculty_name


class Chat(ndb.Model):
    request = ndb.KeyProperty(kind='Requests')
    username = ndb.StringProperty()
    message = ndb.StringProperty()
    message_time = ndb.DateTimeProperty()
    email = ndb.StringProperty()



class Faculty(ndb.Model):
    faculty_name = ndb.StringProperty()
    is_Active = ndb.BooleanProperty()


class Unit(ndb.Model):
    unit_name = ndb.StringProperty()
    is_Active = ndb.BooleanProperty()
    faculty_key = ndb.KeyProperty(kind='Faculty')


class FailedLogins(ndb.Model):
    attempted_email = ndb.StringProperty()
    ip_address = ndb.StringProperty()
    timestamp = ndb.DateTimeProperty()
