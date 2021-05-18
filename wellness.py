import unicodecsv

from flask import Flask, current_app, request, make_response

from flask_httpauth import HTTPBasicAuth

from flask_jwt_extended import current_user, create_access_token, create_refresh_token
from flask_jwt_extended import JWTManager, jwt_required, jwt_refresh_token_required

from flask_jwt_extended.utils import get_jti, get_raw_jwt, get_jwt_identity, decode_token

from mongoengine import *
from mongoengine.errors import DoesNotExist

from models import Users, Metrics, Jwt_tokens

from datetime import datetime, timezone, timedelta

app = Flask("Wellness")
app.config.from_pyfile("production.cfg")

auth = HTTPBasicAuth()
jwt = JWTManager(app)

connect('wellness')
Jwt_tokens.create_index("timestamp", expireAfterSeconds=app.config["JWT_ACCESS_TOKEN_EXPIRES"])

@app.after_request
def auto_refresh_expiring_tokens(response):
    # CHECKS ONLY FOR HTTP 200 RESPONSES
    if response.status == "200 OK":
        # LOGIN OR REFRESH ENDPOINTS DOES NOT NEED REFRESHING ACCESS TOKEN
        if "access-token" not in response.headers and "refreshed-access-token" not in response.headers:
            jwt_token = get_raw_jwt()

            exp_timestamp = jwt_token["exp"]
            now_timestamp = datetime.now(timezone.utc)
            target_timestamp = datetime.timestamp(now_timestamp + timedelta(seconds=app.config["JWT_ACCESS_TOKEN_AUTORENEW"]))

            if target_timestamp > exp_timestamp:
                expired_token = Jwt_tokens()
                expired_token.timestamp = datetime.now(timezone.utc)
                expired_token.jti = jwt_token["jti"]
                expired_token.save()

                refreshed_access_token = create_access_token(identity=get_jwt_identity())
                response.headers["refreshed-access-token"] = refreshed_access_token

    return response

@auth.verify_password
def verify_password(username, password):
    user = auth_user(username, password)

    return user

def auth_user(username, password):
    user = None

    if username == "wellness" and password == "wellness":
        try:
            user = Users.objects.get(user_id="13165938W")

        except DoesNotExist:
            user = None

    return user

@jwt.token_in_blacklist_loader
def check_if_token_is_revoked(jwt_payload):
    token_in_mongodb = None

    jti = jwt_payload["jti"]

    try:
        token_in_mongodb = Jwt_tokens.objects.get(jti=jti)
    except DoesNotExist:
        token_in_mongodb = None
    finally:
        return token_in_mongodb

@jwt.user_loader_callback_loader
def get_user_by_id(user_id):
    user = None

    try:
        user = Users.objects.get(user_id=user_id)

    except DoesNotExist:
        user = None

    finally:
        return user

@app.route('/login', methods=['POST'])
@auth.login_required
def login():
    username = request.authorization['username']
    password = request.authorization['password']

    user = auth_user(username, password)
    if user:
        new_user = Users()

        access_token = create_access_token(identity=str(user.user_id), headers={"myHeader":"myValue"})
        refresh_token = create_refresh_token(user.user_id)

        resp = make_response("User '{}' Logged In".format(user.user_id))
        resp.headers["access-token"] = access_token
        resp.headers["refresh-token"] = refresh_token

        resp.headers["content-type"] = "Application/JSON"

    else:
        resp = make_response("Unauthorized", 403)
        resp.headers["content-type"] = "Text/Plain"

    return resp

@app.route('/refresh', methods=['PUT'])
@jwt_refresh_token_required
def refresh_access_token():
    refreshed_access_token = create_access_token(identity=str(current_user.user_id))

    resp = make_response("User '{}' Access Token Has Been Refreshed".format(current_user.user_id))
    resp.headers["refreshed-access-token"] = refreshed_access_token
    resp.headers["content-type"] = "Application/JSON"

    return resp

@app.route('/logout', methods=['POST'])
@jwt_required
def logout():
    jwt_info = get_raw_jwt()

    try:
        expired_token = Jwt_tokens()
        expired_token.timestamp = datetime.now(timezone.utc)
        expired_token.jti = jwt_info["jti"]
        expired_token.expires = datetime.fromtimestamp(jwt_info["exp"])
        expired_token.save()

        resp = make_response("User {} Logged Out".format(current_user.user_id), 200)
        resp.headers["content-type"] = "application/json"

    except Exception as e:
        pass

    return resp

@app.route("/import", methods=['POST'])
@jwt_required
def import_metrics_file():
    try:
        for (csvName, csvFile) in request.files.items():
            csv_reader = unicodecsv.reader(csvFile, encoding="utf-8")
            next(csv_reader, None)

            for csv_line in csv_reader:
                if csv_line != "":
                    try:
                        csv_metric = Metrics()
                        csv_metric.timestamp = datetime. strptime(csv_line[0], "%d %b %Y %H:%M:%S")
                        csv_metric.energy = float(csv_line[1])
                        csv_metric.reactive_energy = float(csv_line[2])
                        csv_metric.power = float(csv_line[3])
                        csv_metric.maximeter = float(csv_line[4])
                        csv_metric.reactive_power = float(csv_line[5])
                        csv_metric.voltage = float(csv_line[6])
                        csv_metric.intensity = float(csv_line[7])
                        csv_metric.power_factor = float(csv_line[8])
                        csv_metric.save()

                    except Exception as e:
                        pass

    except Exception as e:
        pass

    resp = make_response("Import Process Finished", 200)
    resp.headers["content-type"] = "text/plain"

    return resp


if __name__ == '__main__':
    app.run()
