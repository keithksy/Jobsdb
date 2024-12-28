#https://hub.docker.com/_/python/tags?page=1&name=3.11-slim-bullseye
FROM docker.io/python:3.11-slim-bullseye

COPY . .
RUN pip install -r requirements.txt

#Change your search keyword here for testing purpose
CMD ["python3", "main.py", "--get_jobs", "--keywords", "data-engineer"]