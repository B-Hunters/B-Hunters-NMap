FROM python:3.10-slim
RUN apt-get update && apt-get install nmap -y && apt clean && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir b-hunters==1.0.6 python-nmap 
WORKDIR /app/service
COPY nmapscan /app/service/nmapscan
CMD [ "python", "-m", "nmapscan" ]