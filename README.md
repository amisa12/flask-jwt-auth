# Flask JWT Auth



## Quick Start


1. Activate a virtualenv
```sh
$ virtualenv -p python3 venv
```
1. Install the requirements

```sh
$ pip install -r requirements.txt
```

### Set Environment Variables

Update *app/config.py*, and then run:

```sh
$ export APP_SETTINGS="app.config.DevelopmentConfig"
```

or

```sh
$ export APP_SETTINGS="app.config.ProductionConfig"
```

and 

```sh
$ python3
$>> import os
$>> os.urandom(24)
$>> generated_key
$ export SECRET_KEY="generated_key"
```

### Create DB

Create the databases in `psql`:

```sh
$ psql
# create database lending_v2
# create database lending_v2_test
# \q
```

Create the tables and run the migrations:

```sh
$ python manage.py create_db
$ python manage.py db init
$ python manage.py db migrate
```

### Run the Application

```sh
$ python manage.py runserver
```

So access the application at the address [http://localhost:5000/](http://localhost:5000/)

> Want to specify a different port?

> ```sh
> $ python manage.py runserver -h 0.0.0.0 -p 8080
> ```

### Testing

```sh
$ python manage.py test
```

