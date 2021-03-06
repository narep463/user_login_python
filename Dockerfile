FROM python:3.9.5

WORKDIR /user_python

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY ./app .

EXPOSE 8080

CMD ["python", "./app.py"]