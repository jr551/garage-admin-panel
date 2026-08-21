# syntax=docker/dockerfile:1
# Panel-only image: connects to an existing Garage admin/S3 endpoint.
FROM python:3.12-alpine
LABEL org.opencontainers.image.title="garage-admin-panel" \
      org.opencontainers.image.description="Dependency-free authenticated web control panel for Garage S3" \
      org.opencontainers.image.source="https://github.com/jr551/garage-admin-panel" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY garage_panel.py .
COPY static/ static/
RUN mkdir -p /data && chmod 0770 /data
ENV PANEL_HOST=0.0.0.0 \
    PANEL_PORT=8088 \
    PANEL_AUDIT_LOG=/data/signins.log \
    PANEL_ACTIVITY_LOG=/data/activity.log \
    PANEL_API_KEYS=/data/apikeys.json \
    PANEL_KEY_SECRETS=/data/key-secrets.json \
    PANEL_ARCHIVED_BUCKETS=/data/archived-buckets.json \
    PANEL_BUCKET_NAMES=/data/bucket-names.json \
    PANEL_RESTIC_PASSWORDS=/data/restic-passwords.json \
    PANEL_RESTIC_CHECKS=/data/restic-checks.json \
    PANEL_SESSION_SECRET_FILE=/data/session-secret
VOLUME /data
EXPOSE 8088
HEALTHCHECK --interval=30s --timeout=4s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8088/login',timeout=3)" || exit 1
CMD ["python", "-u", "garage_panel.py"]
