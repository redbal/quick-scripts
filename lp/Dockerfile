FROM python:alpine 

RUN pip install flask

COPY src /src/

EXPOSE $DPORT

ENTRYPOINT ["python", "/src/app.py"]
