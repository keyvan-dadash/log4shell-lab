FROM owasp/modsecurity-crs:3.3.4-nginx-alpine-202301110601
# Copy our Nginx configuration template
COPY default.conf /etc/nginx/templates/conf.d/default.conf.template
# Copy custom rules into ModSecurity rules directory
COPY rules/ /etc/modsecurity/rules/
