nav_bar = {
    "Student": [
        {
            "label":"Dashboard",
            "view":"my_dashboard",
            "icon":"home"
        },
        {
            "label": "Submit New Request",
            "view": "submit_application",
            "icon": "file"
        },
        {
            "label": "Account Settings",
            "view": "settings",
            "icon": "cog"
        }
    ],
    "Tutor": [
        {
            "label": "Dashboard",
            "view": "my_dashboard",
            "icon": "home"
        },
        {
            "label": "Account Settings",
            "view": "settings",
            "icon": "cog"
        }
    ],
    "Admin": [
        {
            "label": "Dashboard",
            "view": "my_dashboard",
            "icon": "home"
        },
        {
            "label": "Faculties",
            "view": "faculties",
            "icon": "cog"
        },
        {
            "label": "Units",
            "view": "units",
            "icon": "cog"
        },
        {
            "label": "Tutors",
            "view": "tutors",
            "icon": "cog"
        },
        {
            "label": "Users",
            "view": "users",
            "icon": "cog"
        },
    ]
}



RECAPTCHA_SECRET = ""
CLIENT_ID = ""
CLIENT_SECRET = ""
TWILIO_SID = ""
TWILIO_TOKEN = ""
MAX_LOGIN_ATTEMPTS = 5

TRELLO_DATA = {
    "API_KEY": "",
    "OAUTH_KEY": "",
    "TOKEN": "",
    "BOARD": "",
    "CALL_BACK": "",
    "CARDS": {
        "ON_STUDENT": "",
        "ON_TUTOR": "",
        "APPROVED": "",
        "REJECTED": ""},
    "CUSTOM": {
        "ExtensionDate": "",
        "RequestID": "",
    }
}