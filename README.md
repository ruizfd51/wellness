# wellness
Python3 Wellness Project API

Funcionalidad de uso descrito en swagger.
Seguridad JWT Integrada.

Crear Virtualenv con requirements.txt
Crear primero bd mongodb con colecciones 'Users', 'Jwt_Tokens', y 'Metrics' (Segun models.py)
Meter un usuario inicial:
 - user_id = "13165938"
 - first_name = "Python"
 - last_name = "Wellness"

hacer login con el swagger

realizar operacion de importacion de datos. Se soportan multiples archivos

curl -X POST http://localhost:5000/import -F "myFile=@monitoring_report.csv"
