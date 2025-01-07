import os
import datetime
import subprocess

def backup_database():
    # Configuración
    DB_NAME = 'xbox_store'
    BACKUP_PATH = 'backups'
    
    # Crear directorio de backups si no existe
    if not os.path.exists(BACKUP_PATH):
        os.makedirs(BACKUP_PATH)
    
    # Nombre del archivo de backup
    date = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{BACKUP_PATH}/backup_{date}"
    
    # Comando para crear el backup
    command = f'mongodump --db {DB_NAME} --out {filename}'
    
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"Backup creado exitosamente: {filename}")
    except subprocess.CalledProcessError as e:
        print(f"Error creando backup: {e}")

if __name__ == '__main__':
    backup_database()