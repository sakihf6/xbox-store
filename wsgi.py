import sys
path = '/home/tzilgameeeee/xbox-store'  # ASEGÚRATE QUE ESTA RUTA SEA CORRECTA
if path not in sys.path:
    sys.path.insert(0, path)

import os
os.environ['FLASK_ENV'] = 'production'
os.environ['SECRET_KEY'] = 'sakih123'

from app import app as application  # Esto debe coincidir con el nombre de tu archivo principal