FROM docker.io/python:3.11-alpine

RUN pip install requests
CMD [“python3”, “./main.py -get_jobs”]