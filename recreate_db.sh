rm -rf migrations
rm app.db
flask db init
flask db migrate
flask db upgrade
python load_users.py