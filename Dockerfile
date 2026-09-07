FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY templates/ ./templates/

# Drop root. The service writes nothing to disk -- it talks to Postgres, Valkey
# and SMTP -- so it needs no ownership changes: /app is root-owned and
# world-readable, which is what we want (the process cannot modify its own code).
# The account is --system with no home, no shell and no password, so it exists
# only to be a uid.
#
# The base tag stays `python:3.11-slim` rather than a digest on purpose. A minor
# version is already a pin; digest-pinning an image that receives security
# patches means a PR per patch, and .github/workflows/launchpad-tests.yml pins
# its job container to `python:3.11-slim` to match this line -- a digest here
# would make that comment untrue.
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin launchpad
USER launchpad

EXPOSE 8000

# --no-access-log: /api/verify carries the raw verification token as a query
# parameter, and uvicorn's access formatter writes the full request line
# including the query string. That would put live bearer tokens for every
# pending user into `docker logs` and any log shipper -- an easier target
# than the database dump the sha256 storage defends against, and the route
# is public (no mpass-auth middleware) so the token is the only credential.
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
