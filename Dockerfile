FROM python:3.10-slim

WORKDIR /my-signature-app

RUN apt-get update && \
    apt-get install -y \
    python3-tk \
    && rm -rf /var/lib/apt/lists/*

COPY ["./requirements.txt", "./"]

RUN pip3 install --quiet -r requirements.txt

COPY . .

CMD ["python", "app/main.py"]