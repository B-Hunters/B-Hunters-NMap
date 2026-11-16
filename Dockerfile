FROM python:3.10-slim
RUN apt-get update && apt-get install nmap -y && apt clean && rm -rf /var/lib/apt/lists/*
# The shared class is built from this repository, not from the published
# release: a worker that calls auth_headers(task) against a release that
# does not have it fails inside the scan.  scripts/build_workers.sh passes
# the local wheel; the default is the published release.
ARG B_HUNTERS_WHEEL=b-hunters==1.4.1
RUN pip install --no-cache-dir ${B_HUNTERS_WHEEL} python-nmap 
WORKDIR /app/service
COPY nmapscan /app/service/nmapscan
CMD [ "python", "-m", "nmapscan" ]