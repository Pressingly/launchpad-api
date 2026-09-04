FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY templates/ ./templates/

EXPOSE 8000

# --no-access-log: /api/verify carries the raw verification token as a query
# parameter, and uvicorn's access formatter writes the full request line
# including the query string. That would put live bearer tokens for every
# pending user into `docker logs` and any log shipper -- an easier target
# than the database dump the sha256 storage defends against, and the route
# is public (no mpass-auth middleware) so the token is the only credential.
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
