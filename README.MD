# Mitigating Circumstances System

This is a full mitigating circumstances system, where students can sign in after email verification and submit applications to the faculty tutors for approval. A full customizable roles (student, tutor & admin) and permissions system are available, to allow admins to modify the system to best fit their needs, including complete set up of their school faculties. Faculty plays a big part in the application, as depending on the student’s faculty which was set on registration, they will only see units in that faculty. For tutors, they will see all requests which have been created for their faculty. SMS Notifications, Google Sign-in, Live-Chat and a Trello Integration, is also built into the application.

The application is written with Python using Flask on Google App Engine (standard environment). 

An example of the site is deployed at https://mc-system-223313.appspot.com (you can contact me for the login details).

## Set up

The application heavily uses APIs as it is built using cloud technologies primarily, so all tokens must be included.

- main.py:22  Change SECRET_KEY to a random string of characters.
- main.py:118 & 274 Change "Bournemouth.ac.uk" to any domain you require.
- main.py:898, 1472, 1491 Change domain to your google domain address.
- main.py:1000 & 1012 Pusher APP ID.
- main.py:1001 & 1015 Pusher APP Key.
- main.py:1521 Unsplash client ID.
- app_settings.py:62    Google recaptcha secret.
- app_settings.py:63    Google oAuth Client ID.
- app_settings.py:64    Google oAuth Client Secret.
- app_settings.py:65    Twillio SID.
- app_settings.py:66    Twillio Token.
- app_settings.py:69    Trello Data (API keys and board/card IDs). On Trello set up 4 lists, "ON_STUDENT", "ON_TUTOR", "APPROVED" & "REJECTED" and get their IDs. Set up 2 custom fields for cards, "ExtensionDate" and "RequestID".
- GoogleRegister.html:54    Change "Bournemouth.ac.uk" to any domain you require.
- Register.html:58  Google Recaptcha site key.
- Register.html:70  Change "Bournemouth.ac.uk" to any domain you require.
- Chat.html:80  Pusher APP Key.

Google App Engine SDK is required.


## API and Technologies used
| Name | Authentication method | Location | Description |
| ---- | --------------------- | -------- | ----------- |
| Unsplash | API Key | Unauthenticated Views | This API call is used to get an image and set it as background on the unauthenticated views. |
| Google ReCaptcha v2 | API Key and Secret | Register | This was added to prevent the register spam getting flooded by a bot. |
| Google Blobstore API | GAE Library | When creating requests | This API is used to store documents and images in the Google Blobstore, so that they can be later read. |
| Google Mail API | GAE Library | When creating/updating requests | This API is used to send emails to users. |
| Google URL Fetch API | GAE Library | When trying to do API calls | This API is used to create web requests. |
| Google Memcache | GAE Library |  | This is used to store the background image url from Unsplash for 3 minutes before expiring which would then cause the background to be re-retrieved. |
| Google Userinfo.V2.Me | OAuthv2 | Login Page & Settings page | This is used when the user tries to register with Google, their basic account information; First Name, Last Name and Google ID is taken. This will then allow them to log in user the Google button when want to. |
| Twillio API | Basic base64 Authorization header | When creating/updating requests | This is used to notify students or tutors when a new request has been added/updated. |
| Trello API | OAuth | When creating/updating requests | This pushes information to a trello board which the system admin can use to see an overview of the application. Trello should only be use for changing status’ and not created new requests. The interaction is duplex so the list changes done in trello reflects in my application and vice versa. Only the admin would have access to this trello account and for safety reasons, it would be better if the admin created his own trello account and was invite into the board. I have used trello to allow the admin to quickly have an overview of the whole system. |
| Google Datastore | GAE Library |  | This is used to store data. |
| CRON | Admin Access Required (app.yaml) |  | Scripts which are run to perform tasks. |
| Trello Webhook | HMAC SHA1 digest | When creating/updating requests | This is used when information from trello is pushed to my application, my application handles it and makes updates based on the changes. |
| Pusher API | MD5 & HMAC SHA256 hex digest | Chat pages | Using websocket technology I have created a chatroom/messaging app which is unique between tutors and a student based on the request. |
| Dropbox Zxcvbn | None required | Register, change password and add new tutor. | This is a password strength estimator. |

## Features
| Name | Description |
| ---- | --------------------- |
| Privacy | Passwords are hashed using salt and chat messages are stored in base 64. |
| Email Validation | To confirm the user’s access to the account and to confirm their identity. |
| Password reset | Allows the user to reset their password if they forget. Email is sent to them if the account exists in the datastore. |
| CRON Jobs| -  Disable student accounts which are past the graduation date.|
||- Delete failed logins, to allow users/ip address to retry.|
||- Delete password reset requests which are past their expiry date. |
| Ajax | - Process password reset requests.|
||- Get unit list based on faculty.|
||- Delete the attachment from the request and trello. |
| Flask | Micro web framework which allowed me to create the view routes. |
| Google Sign In | Allows a user to sign into the application using their google. If they did not register with google initially, they can still link their account in account settings. They can also remove this option in the account settings. In order to test this functionality I would recommend logging into the student account, going into settings and connecting to google, then signing out and logging in with google instead of the password email combination. |
| Jinja2 | Generates the HTML. |
| Locking out IP addresses after 5 failed attempts | If the user fails the login 5 times, the ip address is blocked temporally. They can still login with Google if they want to.  It is possible to get both a ip and user lock at once. |
| Locking users after 5 failed attempts | If the user fails the login 5 times, the user is blocked temporally. They can still login with Google if they want to. This means you can’t log into this user on any IP until the soft ban time is over. |
| Create/Edit requests | Students can create a new extension request which will then need to be approved by a tutor. Students can click on the chat icon to send further messages to the tutor if it is required. The request is also created in trello for the system admin to see the overview of the system. |

## Possible Improvements
- More administative tools for users with admin role
- Make the system more "vanilla" by removing auth tokens from backend code and add it to front end.

## Screenshots
### Register
<img src="https://image.prntscr.com/image/YD8kiaJ1S_i73n6i8aTXeQ.png" width="70%"></img>

### Login
<img src="https://image.prntscr.com/image/76SK8QJtQkuI7DOJBcN-Ng.png" width="70%"></img>

### Student
#### Home
<img src="https://image.prntscr.com/image/zMrl0dPJRje2swj3XAO2iQ.png" width="70%"></img>
#### Submit New Request
<img src="https://image.prntscr.com/image/TMVZl7SzTLGHu00OdmGKvA.png" width="70%"></img>
#### Account Settings
<img src="https://image.prntscr.com/image/VlO2JNSSTjmXTV12UQheqg.png" width="70%"></img>
#### Approved Application
<img src="https://image.prntscr.com/image/LBCofgGZT3W-G4ijPpjNCQ.png" width="70%"></img>
### Tutor
#### Reqeust Approval
<img src="https://image.prntscr.com/image/1AcfJZ3XTROrhexrMXmXmw.png" width="70%"></img>
### Admin
#### Faculties
<img src="https://image.prntscr.com/image/KITk5G_QQxK98RCuel4DHw.png" width="70%"></img>
#### Units
<img src="https://image.prntscr.com/image/CEDJuh4bTBGNaCUzPMYEnQ.png" width="70%"></img>
#### Tutors
<img src="https://image.prntscr.com/image/4FNDIKL5Q_qwScH19KV4Sw.png" width="70%"></img>
#### Users
<img src="https://image.prntscr.com/image/NSejQYZBQ6ScIyObkxnWEg.png" width="70%"></img>
<img src="https://image.prntscr.com/image/SbiGQZS3SDuvtGpv9hNx4g.png" width="70%"></img>

### Chat
<img src="https://image.prntscr.com/image/zCK-flalQ7Oqt9KJL43Xzg.png" width="70%"></img>


### Trello
<img src="https://image.prntscr.com/image/XJh7JfeBRIusv2mdnZORjg.png" width="70%"></img>
<img src="https://image.prntscr.com/image/O-Q8cWDhRrav4PBf5Otw5A.png" width="70%"></img>
### SMS
<img src="https://image.prntscr.com/image/20B6wutQQ1qLEht2QB_UWw.png" width="50%"></img>
### Email
<img src="https://image.prntscr.com/image/Th2cu1LaR9qeN2t8Pzxu8Q.png" width="90%"></img>
