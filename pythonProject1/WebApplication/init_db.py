import os
from WebApplication.app import db, app, add_predefined_roles_and_users


# Define the path to the SQLite database file
instance_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance')
db_path = os.path.join(instance_folder, 'Database.db')


if os.path.exists(db_path):
    os.remove(db_path)
    print(f"Removed database file: {db_path}")
else:
    print(f"Database file not found at {db_path}")

# Ensure that the 'instance' directory exists
if not os.path.exists(instance_folder):
    os.makedirs(instance_folder)

print("Database path:", db_path)

# Manually remove the database file if it exists
if os.path.exists(db_path):
    os.remove(db_path)


# Initialize the database
with app.app_context():
    db.drop_all()  # removes all tables (for development only, remove in production)
    db.create_all()
    add_predefined_roles_and_users() # Add predefined users during startup
    print("Database created successfully.")