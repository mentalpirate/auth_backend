# Auth Backend with Supabase + FastAPI

This is a demo project for an authentication backend using Supabase and FastAPI.

## Environment Setup

1. Create a new Python virtual environment: `python -m venv env`
2. Activate the virtual environment: `source env/bin/activate`
3. Install the project dependencies: `pip install -r requirements.txt`
4. Set the environment variables:
   - `SUPABASE_URL`
   - `SUPABASE_ANON_KEY`
   - `SUPABASE_SERVICE_ROLE_KEY`
   - `API_BASE_URL`
   - `FRONTEND_BASE_URL`
   - `COOKIE_DOMAIN`
   - `COOKIE_SECURE`
   - `COOKIE_SAMESITE`
   - `ACCESS_TOKEN_COOKIE`
   - `REFRESH_TOKEN_COOKIE`

## Running the Application

1. Run the application using `uvicorn`: `uvicorn app.main:app --reload`
2. Open a web browser and navigate to `http://localhost:8000/docs` to access the FastAPI documentation.

## Development

The project uses `FastAPI` as the web framework and `Supabase` as the database.
The code is organized into the following directories:

- `app/main.py`: The main application file.
- `app/api`: The python file containing api routes
- `app/models`: The data models used by the application.
- `app/core`: contain project configs.
- `app/utils`: The utility functions used by the application.

## Deployment

The project can be deployed to any platform that supports Python and HTTP servers.
The deployment process involves the following steps:

1. Create a virtual enviroment `python -m venv venv`
2. Install the project dependencies: `pip install -r requirements.txt`
3. Set the environment variables in `config_sample.py`
4. Run the application using `uvicorn`: `uvicorn main:app`
5. The uvicorn will server on http://127.0.0.1:8000
6. Api Documentation is available in http://127.0.0.1:8000/docs

