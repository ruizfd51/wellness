from mongoengine import *

class Users(Document):
    user_id = StringField(max_length=9)
    first_name = StringField(max_length=50)
    last_name = StringField(max_length=50)
    email = StringField(required=True)

    meta = {"collection":"users", "allow_inheritance": False}

class Jwt_tokens(Document):
    timestamp = DateTimeField()
    jti = StringField(unique=True)
    expires = DateTimeField()

    meta = {"collection":"jwt_tokens"}

class Metrics(Document):
    timestamp = DateTimeField(unique=True)
    energy = DecimalField()
    reactive_energy = DecimalField()
    power = DecimalField()
    maximeter = DecimalField()
    reactive_power = DecimalField()
    voltage = DecimalField()
    intensity = DecimalField()
    power_factor = DecimalField()

    meta = {"collection":"metrics", "allow_inheritance": False}
