user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    upstream auth_service {
        server auth:80;
    }

    server {
        listen 80;
        server_name upstream.example.com;

        root /var/www/html;
        index index.php index.html;

        # Log authentication headers
        log_format auth_headers '$remote_addr - $http_x_rcloudauth_username [$time_local] '
                               '"$request" $status $body_bytes_sent '
                               '"$http_referer" "$http_user_agent" '
                               '"$http_x_rcloudauth_email" "$http_x_rcloudauth_groups"';
        access_log /var/log/nginx/access.log auth_headers;

        # Outpost endpoint for health checks
        location /outpost.rcloudauth {
            default_type application/json;
            return 200 '{"status": "OK", "service": "Upstream-Nginx", "version": "1.0"}';
            add_header X-Auth-Service "Upstream-Nginx" always;
        }

        # Protected application endpoint
        location / {
            auth_request /auth;
            error_page 401 = @rcloudauth_signin;

            auth_request_set $rcloudauth_username $upstream_http_x_rcloudauth_username;
            auth_request_set $rcloudauth_groups $upstream_http_x_rcloudauth_groups;
            auth_request_set $rcloudauth_email $upstream_http_x_rcloudauth_email;
            auth_request_set $rcloudauth_name $upstream_http_x_rcloudauth_name;
            auth_request_set $rcloudauth_uid $upstream_http_x_rcloudauth_uid;

            try_files $uri $uri/ /index.php?$query_string;
        }

        # Redirect to auth service on 401
        location @rcloudauth_signin {
            internal;
            return 302 http://auth:80/outpost.rcloudauth/start?rd=$scheme://$http_host$request_uri;
        }

        # Proxy to auth service for validation
        location = /auth {
            internal;
            proxy_pass http://auth_service/auth;
            proxy_set_header Host $host;
            proxy_set_header X-Original-URL $scheme://$http_host$request_uri;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
        }

        # PHP processing (if applicable)
        location ~ \.php$ {
            include fastcgi_params;
            fastcgi_pass 127.0.0.1:9000;
            fastcgi_index index.php;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param HTTP_X_RCLOUDAUTH_USERNAME $http_x_rcloudauth_username;
            fastcgi_param HTTP_X_RCLOUDAUTH_GROUPS $http_x_rcloudauth_groups;
            fastcgi_param HTTP_X_RCLOUDAUTH_EMAIL $http_x_rcloudauth_email;
            fastcgi_param HTTP_X_RCLOUDAUTH_NAME $http_x_rcloudauth_name;
            fastcgi_param HTTP_X_RCLOUDAUTH_UID $http_x_rcloudauth_uid;
        }

        # Static files
        location ~* \.(css|js|png|jpg|jpeg|gif|ico)$ {
            expires max;
            log_not_found off;
        }
    }
}