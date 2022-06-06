# Setup Flask Rest API Application using Marshmallow

# At first create virutal environment(env)
```
virtualenv env_name

and then 

cd env_name
```

### Install Requirements in the env

```
pip install -r requirements.txt
```

### Migration Commands

```
1) one time command (Intantiate the Migrate):
==> flask db init 

2) Creating migration files (Command to execute after change in model code):
==> flask db migrate 

3) Applying migrations to database table (Command to execute after change in model code):
==> flask db upgrade

4) To reverse the migration:
==> flask db downgrade

```


### To run Flask Local Development Server

```

python app.py 

```
