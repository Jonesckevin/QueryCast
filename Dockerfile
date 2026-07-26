# QueryCast Frontend — nginx static file server (hardened, non-root)
FROM nginx:alpine

# ── Non-root user (UID/GID 1000) ──
# Running nginx as a non-root user eliminates container privilege-escalation risk.
# Port 8080 is used because ports <1024 require CAP_NET_BIND_SERVICE as root.
RUN addgroup -g 1000 -S appgroup && \
    adduser  -u 1000 -S appuser -G appgroup && \
    # Remove 'user nginx;' directive — nginx ignores it when already non-root,
    # but some versions fail to start if they can't setuid to the named user.
    sed -i '/^user /d' /etc/nginx/nginx.conf && \
    # Grant appuser write access to all directories nginx needs at runtime
    chown -R appuser:appgroup \
        /var/cache/nginx \
        /var/log/nginx \
        /etc/nginx/conf.d \
        /usr/share/nginx/html && \
    # Pre-create PID file with correct ownership
    touch /var/run/nginx.pid && \
    chown appuser:appgroup /var/run/nginx.pid

# ── Static assets ──
COPY index.html  /usr/share/nginx/html/
COPY favicon.svg /usr/share/nginx/html/
COPY css/        /usr/share/nginx/html/css/
COPY js/         /usr/share/nginx/html/js/
COPY logo/       /usr/share/nginx/html/logo/

# ── nginx configuration ──
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d/default.conf

# ── Drop privileges ──
USER appuser
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:8080/index.html || exit 1

CMD ["nginx", "-g", "daemon off;"]
