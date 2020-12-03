from flask_appbuilder.security.views import AuthDBView
from flask_appbuilder import expose
from flask_login import login_user
from flask import request, redirect, session
import superset
from superset import app
from superset.security.manager import SupersetSecurityManager
import requests
import logging
import os
#con la api mockeada esto se testea haciendo
#http://localhost:9000/login/?token=a
logger = logging.getLogger(__name__)

def get_role(user_data):
    if user_data is None or 'roles' not in user_data:
        return None
    role = user_data['roles']
    public_role = os.environ['PUBLIC_ROLE']
    admin_role = os.environ['ADMIN_ROLE']
    for r in role:
        if r == admin_role:
            return "Admin"
    for r in role:
        if r == public_role:
            return "Alpha"
    return None


def process_token_api(token):
    try:
        headers  = {"Authorization": "Bearer " + token}
        url = os.environ['KEYCLOAK_BASE_URL'] + "/auth/realms/"+os.environ['KEYCLOAK_REALM']+"/protocol/openid-connect/userinfo"
        response = requests.get(url , headers = headers)
    except Exception as e:
        logger.info("error file fetch user details: " + str(e))
        return None
    if response.status_code in [200]:
        return response.json()
    else:
       logger.info("error while fetching user details response code is : " + str(response.status_code))

class CustomAuthDBView(AuthDBView):
    login_template = 'appbuilder/general/security/login_db.html'

    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        logger.info("came inside login")
        if superset.app.config.get('LOGIN_WITH_TOKEN') is False:
            return super(CustomAuthDBView, self).login()
        token = request.values.get('token')
        nextUrl= request.values.get('next')
        logger.info("This next: " + str(nextUrl))

        session['token']=token
        coo = request.cookies
        logger.info("Cookiee: " + str(coo))
        if token is None:
             token = request.cookies.get('superset_token')
        if not token:
            logger.info("Token Cookie not found")
            return "User not Authorized"

        user_data = process_token_api(token)

        if not user_data:
            return "User not Authorized"
        
        user = self.appbuilder.sm.find_user(
            username=user_data["preferred_username"]
        )

        if not user:
            role = get_role(user_data)
            if role == None:
                return "R: User not Authorized"
            logger.info("Creating User")
            logger.info("User Role: " + str(role))
            # create an user with the data session
            # and assign to him/her a default role
            user = self.appbuilder.sm.add_user(
                username=user_data["preferred_username"],
                first_name=user_data["preferred_username"],
                last_name=user_data["preferred_username"],
                email=user_data["email"],
                role=self.appbuilder.sm.find_role(role),
                password = "preferred_username"
            )
        # now, login the user
        login_user(user, remember=True)

        # with standalone = True we remove the title and the
        # menu of Superset in our embedding.
        #standalone = str(request.args.get('standalone'))

        if user_data is not None and "company" in user_data.keys():
            session["company"] = "Infosys"#user_data["company"]
        logger.info("***************** USER LOGGED IN *************************")
        return redirect(nextUrl)


class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView
    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)