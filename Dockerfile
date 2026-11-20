FROM python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
RUN apt-get update && apt-get install nmap -y && apt clean && rm -rf /var/lib/apt/lists/*
# The shared class is built from this repository, not from the published
# release: a worker that calls auth_headers(task) against a release that
# does not have it fails inside the scan.  scripts/build_workers.sh passes
# the local wheel; the default is the published release.
ARG B_HUNTERS_WHEEL=b-hunters==1.5.3
RUN pip install --no-cache-dir ${B_HUNTERS_WHEEL} python-nmap 
WORKDIR /app/service
COPY nmapscan /app/service/nmapscan
CMD [ "python", "-m", "nmapscan" ]