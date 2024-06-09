from typing import Dict
import json
import uuid

from flask import Flask, render_template, request, jsonify, redirect, url_for
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier

# from .models import Credential, UserAccount
#######
from typing import Optional, List
from dataclasses import dataclass, field

from webauthn.helpers.structs import AuthenticatorTransport

@dataclass
class Credential:
    id: bytes
    public_key: bytes
    sign_count: int
    transports: Optional[List[AuthenticatorTransport]] = None

@dataclass
class UserAccount:
    username: str
    credentials: List[Credential] = field(default_factory=list)

@dataclass
class SessionVar:
    username: str
    expected_challenge: str

# A simple way to persist credentials by user ID
# in_memory_db: Dict[str, UserAccount] = {}

# A simple way to persist challenges until response verification
# current_registration_challenge = None
# current_authentication_challenge = None

in_memory_db: dict[str, UserAccount] = {} 
in_memory_session: dict[str, SessionVar] = {}

app = Flask(__name__)

################
#
# Functions
#
################

def update_session(username: str, challenge: str) -> None:
    if username in in_memory_session:
        in_memory_session[username].expected_challenge = challenge
    else:
        session = SessionVar(username=username, expected_challenge=challenge)
        in_memory_session[username] = session
    return

################
#
# Relying Party Configuration
#
################
port = "8000"

rp_id = "localhost"
origin = "http://" + rp_id + ":" + port
rp_name = "Sample Relying Party"
#user_id = "some_random_user_identifier_like_a_uuid"
username = f"your.name@{rp_id}"
user_id = str(uuid.uuid4())
#username = "your.name@test.com"

################
#
# Views
#
################

@app.route('/', methods=['GET'])
def root():
    context = {
        "rp_id": rp_id,
        "rp_name": rp_name,
        "origin": origin,
        "port": port,
    }
    return render_template('index.html', **context)

@app.route('/sys', methods=['GET','POST'])
def sys():
    global rp_id
    global origin
    global rp_name
    if request.method == 'GET':
        context = {
            "rp_id": rp_id,
            "rp_name": rp_name,
            "origin": origin,
            "port": port
        }
        return render_template('sys.html', **context, user_data=in_memory_db)
    else:
        rp_id = request.form['rp_id']
        origin = request.form['origin']
        rp_name = request.form['rp_name']
        return redirect(url_for('root'))

################
#
# Registration
#
################

@app.route('/register', methods=['POST'])
def register():
    global current_authentication_challenge
    username = request.form['username']

    if username not in in_memory_db:
        new_user = UserAccount(username=username)
        in_memory_db[username] = new_user
    
    user = in_memory_db[username]

    # webauthn module function
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=user.username,
        user_name=user.username,
        exclude_credentials=[
            {"id": cred.id, "transports": cred.transports, "type": "public-key"}
            for cred in user.credentials
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ],
    )
    # webauthn module function
    response = options_to_json(options)
    # response = jsonify({'message': 'User registered successfully!'})

    # current_authentication_challenge = options.challenge
    update_session(user.username,options.challenge)
    return response

@app.route("/verify-registration", methods=["POST"])
def handler_verify_registration():
    post_payload = request.get_data()
    json_data = json.loads(post_payload)
    body = bytes(json_data.get("original_json"), encoding="utf-8")
    username = json_data.get("username")

    if username in in_memory_session: 
        current_challenge = in_memory_session[username].expected_challenge
    else:
        current_challenge = None

    try:
        credential = RegistrationCredential.parse_raw(body)
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=current_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
        )
    except Exception as err:
        return {"verified": False, "msg": str(err), "status": 400}

    user = in_memory_db[username]

    new_credential = Credential(
        id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        transports=json.loads(body).get("transports", []),
    )

    user.credentials.append(new_credential)

    return {"verified": True}

################
#
# Authentication
#
################

@app.route('/authenticate', methods=['POST'])
def authenticate():
    username = request.form['username']

    if username in in_memory_db:
        user = in_memory_db[username]

        options = generate_authentication_options(
            rp_id=rp_id,
            allow_credentials=[
                {"type": "public-key", "id": cred.id, "transports": cred.transports}
                for cred in user.credentials
            ],
            user_verification=UserVerificationRequirement.REQUIRED,
        )

        # current_authentication_challenge = options.challenge
        update_session(user.username,options.challenge)
        response = options_to_json(options)
    else:
        response = jsonify({'message': 'User does not exist!'})

    return response

@app.route('/verify-authentication', methods=['POST'])
def handler_verify_authentication():
    post_payload = request.get_data()
    json_data = json.loads(post_payload)
    body = bytes(json_data.get("original_json"), encoding="utf-8")
    username = json_data.get("username")

    try:
        credential = AuthenticationCredential.parse_raw(body)

        # Find the user's corresponding public key
        user = in_memory_db[username]
        user_credential = None
        for _cred in user.credentials:
            if _cred.id == credential.raw_id:
                user_credential = _cred

        if user_credential is None:
            raise Exception("Could not find corresponding public key in DB")

        if username in in_memory_session: 
            current_challenge = in_memory_session[username].expected_challenge
        else:
            current_challenge = None

        # Verify the assertion
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=current_challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=user_credential.public_key,
            credential_current_sign_count=user_credential.sign_count,
            require_user_verification=True,
        )
    except Exception as err:
        return {"verified": False, "msg": str(err), "status": 400}

    # Update our credential's sign count to what the authenticator says it is now
    user_credential.sign_count = verification.new_sign_count

    return {"verified": True}


if __name__ == '__main__':
###    start_scheduler_thread()
    app.run(debug=True, port=port)
#    app.run(debug=True, port=os.getenv("PORT", default=5000))
    