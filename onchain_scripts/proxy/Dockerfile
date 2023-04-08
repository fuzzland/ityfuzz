FROM python:3-alpine

COPY . /app
WORKDIR /app
RUN pip3 install -r requirements.txt
EXPOSE 8000

CMD gunicorn main:app

